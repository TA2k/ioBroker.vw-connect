.class Lcom/google/android/filament/android/DisplayHelper$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/hardware/display/DisplayManager$DisplayListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/google/android/filament/android/DisplayHelper;->attach(Lcom/google/android/filament/Renderer;Landroid/view/Display;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lcom/google/android/filament/android/DisplayHelper;

.field final synthetic val$display:Landroid/view/Display;


# direct methods
.method public constructor <init>(Lcom/google/android/filament/android/DisplayHelper;Landroid/view/Display;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/android/DisplayHelper$1;->this$0:Lcom/google/android/filament/android/DisplayHelper;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/google/android/filament/android/DisplayHelper$1;->val$display:Landroid/view/Display;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public onDisplayAdded(I)V
    .locals 0

    .line 1
    return-void
.end method

.method public onDisplayChanged(I)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/android/DisplayHelper$1;->val$display:Landroid/view/Display;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/view/Display;->getDisplayId()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-ne p1, v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lcom/google/android/filament/android/DisplayHelper$1;->this$0:Lcom/google/android/filament/android/DisplayHelper;

    .line 10
    .line 11
    invoke-static {p0}, Lcom/google/android/filament/android/DisplayHelper;->a(Lcom/google/android/filament/android/DisplayHelper;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public onDisplayRemoved(I)V
    .locals 0

    .line 1
    return-void
.end method
