.class public final synthetic Lb0/w0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lb0/a0;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lb0/a1;


# direct methods
.method public synthetic constructor <init>(Lb0/a1;Lb0/a1;I)V
    .locals 0

    .line 1
    iput p3, p0, Lb0/w0;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lb0/w0;->e:Lb0/a1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lb0/b0;)V
    .locals 0

    .line 1
    iget p1, p0, Lb0/w0;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lb0/w0;->e:Lb0/a1;

    .line 4
    .line 5
    packed-switch p1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget p1, Landroidx/camera/core/ImageProcessingUtil;->a:I

    .line 9
    .line 10
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    sget p1, Landroidx/camera/core/ImageProcessingUtil;->a:I

    .line 15
    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
