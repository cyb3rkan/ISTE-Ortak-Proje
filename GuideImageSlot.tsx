import type { GuideImage } from "../providerGuides";

interface GuideImageSlotProps {
  slotId: string;
  stepNumber: number;
  /** Verilirse gerçek görsel gösterilir; yoksa açık bir yer tutucu. */
  image?: GuideImage;
}

/**
 * Rehber adımı için görsel alanı. Görsel eklenene kadar, tamamlanmış bir
 * ekran görüntüsüyle karıştırılmayacak, kesik çizgili metin yer tutucusu
 * gösterir. Görsel eklemek için `providerGuides.ts` içinde adıma `image`
 * vermek yeterlidir; bu bileşen değiştirilmeden kalabilir.
 */
export function GuideImageSlot({ slotId, stepNumber, image }: GuideImageSlotProps) {
  if (image) {
    return (
      <img
        src={image.src}
        alt={image.alt}
        loading="lazy"
        className="mt-3 w-full rounded-md border border-surface-border"
        data-guide-image-slot={slotId}
      />
    );
  }

  return (
    <div
      data-guide-image-slot={slotId}
      className="mt-3 flex min-h-20 items-center justify-center rounded-md border-2 border-dashed border-slate-700 px-3 py-4 text-center text-xs text-slate-500"
    >
      Görsel yer tutucusu — Adım {stepNumber} için gerçek ekran görüntüsü daha sonra
      eklenecek.
    </div>
  );
}
