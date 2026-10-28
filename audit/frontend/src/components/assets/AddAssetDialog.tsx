"use client";

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Loader2, Plus } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/components/ui/toast";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

const SENSITIVITY = [
  { value: "internal", label: "Internal" },
  { value: "confidential", label: "Confidential" },
  { value: "regulated", label: "Regulated / PII" },
  { value: "secret", label: "Secret" },
];

const ASSET_TYPES = [
  { value: "domain", label: "Web / TLS", placeholder: "api.zerodha.com" },
  { value: "ssh", label: "SSH", placeholder: "git.company.com" },
  { value: "smtp", label: "Mail (SMTP)", placeholder: "smtp.company.com" },
  { value: "postgres", label: "PostgreSQL", placeholder: "db.company.com" },
  { value: "mysql", label: "MySQL (TLS)", placeholder: "mysql.company.com" },
  { value: "mongodb", label: "MongoDB (TLS)", placeholder: "mongo.company.com" },
  { value: "amqp", label: "AMQP (RabbitMQ)", placeholder: "rabbit.company.com" },
  { value: "grpc", label: "gRPC (TLS)", placeholder: "grpc.company.com" },
];

export function AddAssetDialog() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [identifier, setIdentifier] = useState("");
  const [assetType, setAssetType] = useState("domain");
  const [sensitivity, setSensitivity] = useState("internal");
  const [shake, setShake] = useState(false);

  const mut = useMutation({
    mutationFn: () =>
      api.assets.create({
        type: assetType,
        name: name || undefined,
        identifier: identifier.trim(),
        data_sensitivity: sensitivity,
      }),
    onSuccess: () => {
      toast({ title: "Asset added", variant: "success" });
      qc.invalidateQueries({ queryKey: ["assets"] });
      setOpen(false);
      setName("");
      setIdentifier("");
      setAssetType("domain");
      setSensitivity("internal");
    },
    onError: (e) => {
      setShake(true);
      setTimeout(() => setShake(false), 500);
      toast({
        title: "Could not add asset",
        description: (e as Error).message,
        variant: "error",
      });
    },
  });

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!identifier.trim()) {
      setShake(true);
      setTimeout(() => setShake(false), 500);
      return;
    }
    mut.mutate();
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus className="h-4 w-4" /> Add asset
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add an asset</DialogTitle>
          <DialogDescription>
            Add a host to scan for quantum-vulnerable cryptography — web/TLS, SSH,
            mail, database, message queue, or gRPC.
          </DialogDescription>
        </DialogHeader>

        <motion.form
          onSubmit={onSubmit}
          className="space-y-4"
          animate={shake ? { x: [0, -8, 8, -6, 6, -3, 3, 0] } : {}}
          transition={{ duration: 0.45 }}
        >
          <div className="space-y-2">
            <Label htmlFor="a-name">Asset name (optional)</Label>
            <Input
              id="a-name"
              placeholder="Production API"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          <div className="space-y-2">
            <Label>Asset type</Label>
            <div className="grid grid-cols-2 gap-2">
              {ASSET_TYPES.map((t) => (
                <button
                  type="button"
                  key={t.value}
                  onClick={() => setAssetType(t.value)}
                  className={cn(
                    "rounded-lg border px-3 py-2 text-sm transition-colors",
                    assetType === t.value
                      ? "border-quantum bg-quantum/10 text-quantum"
                      : "hover:bg-accent"
                  )}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="a-host">Host</Label>
            <Input
              id="a-host"
              placeholder={ASSET_TYPES.find((t) => t.value === assetType)?.placeholder ?? "api.company.com"}
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              required
            />
          </div>

          <div className="space-y-2">
            <Label>Data sensitivity</Label>
            <div className="grid grid-cols-2 gap-2">
              {SENSITIVITY.map((s) => (
                <button
                  type="button"
                  key={s.value}
                  onClick={() => setSensitivity(s.value)}
                  className={cn(
                    "rounded-lg border px-3 py-2 text-sm transition-colors",
                    sensitivity === s.value
                      ? "border-quantum bg-quantum/10 text-quantum"
                      : "hover:bg-accent"
                  )}
                >
                  {s.label}
                </button>
              ))}
            </div>
          </div>

          <DialogFooter className="gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => setOpen(false)}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={mut.isPending}>
              {mut.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                "Add asset"
              )}
            </Button>
          </DialogFooter>
        </motion.form>
      </DialogContent>
    </Dialog>
  );
}
