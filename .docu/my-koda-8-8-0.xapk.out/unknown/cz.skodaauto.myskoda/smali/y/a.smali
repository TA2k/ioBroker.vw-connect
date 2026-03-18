.class public final Ly/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Ljava/io/ByteArrayOutputStream;

    const/16 v1, 0x200

    invoke-direct {v0, v1}, Ljava/io/ByteArrayOutputStream;-><init>(I)V

    iput-object v0, p0, Ly/a;->a:Ljava/lang/Object;

    .line 3
    new-instance v1, Ljava/io/DataOutputStream;

    invoke-direct {v1, v0}, Ljava/io/DataOutputStream;-><init>(Ljava/io/OutputStream;)V

    iput-object v1, p0, Ly/a;->b:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/view/contentcapture/ContentCaptureSession;Landroid/view/View;)V
    .locals 0

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    iput-object p1, p0, Ly/a;->a:Ljava/lang/Object;

    .line 11
    iput-object p2, p0, Ly/a;->b:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 2

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    const-class v0, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedOutputSizeQuirk;

    .line 6
    sget-object v1, Lx/a;->a:Ld01/x;

    invoke-virtual {v1, v0}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    move-result-object v0

    .line 7
    check-cast v0, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedOutputSizeQuirk;

    iput-object v0, p0, Ly/a;->a:Ljava/lang/Object;

    .line 8
    new-instance v0, Lj51/i;

    const/4 v1, 0x4

    invoke-direct {v0, p1, v1}, Lj51/i;-><init>(Ljava/lang/String;I)V

    iput-object v0, p0, Ly/a;->b:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a(J)Landroid/view/autofill/AutofillId;
    .locals 1

    .line 1
    iget-object v0, p0, Ly/a;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/view/contentcapture/ContentCaptureSession;

    .line 4
    .line 5
    iget-object p0, p0, Ly/a;->b:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Landroid/view/View;

    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/view/View;->getAutofillId()Landroid/view/autofill/AutofillId;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-virtual {v0, p0, p1, p2}, Landroid/view/contentcapture/ContentCaptureSession;->newAutofillId(Landroid/view/autofill/AutofillId;J)Landroid/view/autofill/AutofillId;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method
