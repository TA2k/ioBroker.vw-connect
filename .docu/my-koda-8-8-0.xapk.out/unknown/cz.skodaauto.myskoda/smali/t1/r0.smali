.class public final synthetic Lt1/r0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt1/w0;


# direct methods
.method public synthetic constructor <init>(Lt1/w0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lt1/r0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lt1/r0;->e:Lt1/w0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lt1/r0;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lt1/r0;->e:Lt1/w0;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-interface {p0}, Lt1/w0;->onCancel()V

    .line 9
    .line 10
    .line 11
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    return-object p0

    .line 14
    :pswitch_0
    invoke-interface {p0}, Lt1/w0;->c()V

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
