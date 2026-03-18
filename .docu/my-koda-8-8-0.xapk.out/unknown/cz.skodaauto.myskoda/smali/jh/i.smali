.class public final synthetic Ljh/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljh/l;


# direct methods
.method public synthetic constructor <init>(Ljh/l;I)V
    .locals 0

    .line 1
    iput p2, p0, Ljh/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ljh/i;->e:Ljh/l;

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
    iget v0, p0, Ljh/i;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Ljh/i;->e:Ljh/l;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Ljh/l;->k:Llx0/q;

    .line 9
    .line 10
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lzb/k0;

    .line 15
    .line 16
    const-string v0, "DATA_POLLING_TAG"

    .line 17
    .line 18
    invoke-static {p0, v0}, Lzb/k0;->a(Lzb/k0;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_0
    invoke-static {p0}, Ljh/l;->a(Ljh/l;)V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
