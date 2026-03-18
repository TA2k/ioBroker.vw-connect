.class public final synthetic Lv70/a;
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
    iput p2, p0, Lv70/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lv70/a;->e:Ld01/h0;

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
    iget v0, p0, Lv70/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ldw0/a;

    .line 7
    .line 8
    const-string v0, "$this$engine"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lv70/a;->e:Ld01/h0;

    .line 14
    .line 15
    iput-object p0, p1, Ldw0/a;->b:Ld01/h0;

    .line 16
    .line 17
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_0
    check-cast p1, Lzv0/e;

    .line 21
    .line 22
    const-string v0, "$this$HttpClient"

    .line 23
    .line 24
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    new-instance v0, Lv70/a;

    .line 28
    .line 29
    const/4 v1, 0x1

    .line 30
    iget-object p0, p0, Lv70/a;->e:Ld01/h0;

    .line 31
    .line 32
    invoke-direct {v0, p0, v1}, Lv70/a;-><init>(Ld01/h0;I)V

    .line 33
    .line 34
    .line 35
    iget-object p0, p1, Lzv0/e;->d:Lay0/k;

    .line 36
    .line 37
    new-instance v1, Lpc/a;

    .line 38
    .line 39
    const/4 v2, 0x3

    .line 40
    invoke-direct {v1, p0, v0, v2}, Lpc/a;-><init>(Lay0/k;Lay0/k;I)V

    .line 41
    .line 42
    .line 43
    iput-object v1, p1, Lzv0/e;->d:Lay0/k;

    .line 44
    .line 45
    goto :goto_0

    .line 46
    nop

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
