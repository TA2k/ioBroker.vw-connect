.class public final Lr50/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ld01/h0;


# direct methods
.method public synthetic constructor <init>(Ld01/h0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lr50/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lr50/a;->e:Ld01/h0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lr50/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lzv0/e;

    .line 7
    .line 8
    const-string v0, "$this$HttpClient"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    new-instance v0, Lr50/a;

    .line 14
    .line 15
    iget-object p0, p0, Lr50/a;->e:Ld01/h0;

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    invoke-direct {v0, p0, v1}, Lr50/a;-><init>(Ld01/h0;I)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p1, Lzv0/e;->d:Lay0/k;

    .line 22
    .line 23
    new-instance v1, Lpc/a;

    .line 24
    .line 25
    const/4 v2, 0x3

    .line 26
    invoke-direct {v1, p0, v0, v2}, Lpc/a;-><init>(Lay0/k;Lay0/k;I)V

    .line 27
    .line 28
    .line 29
    iput-object v1, p1, Lzv0/e;->d:Lay0/k;

    .line 30
    .line 31
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_0
    check-cast p1, Ldw0/a;

    .line 35
    .line 36
    const-string v0, "$this$engine"

    .line 37
    .line 38
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Lr50/a;->e:Ld01/h0;

    .line 42
    .line 43
    iput-object p0, p1, Ldw0/a;->b:Ld01/h0;

    .line 44
    .line 45
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    return-object p0

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
