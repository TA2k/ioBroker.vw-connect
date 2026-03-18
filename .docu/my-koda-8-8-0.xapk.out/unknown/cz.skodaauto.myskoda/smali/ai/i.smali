.class public final synthetic Lai/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lai/l;


# direct methods
.method public synthetic constructor <init>(Lai/l;I)V
    .locals 0

    .line 1
    iput p2, p0, Lai/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lai/i;->e:Lai/l;

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
    .locals 4

    .line 1
    iget v0, p0, Lai/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lai/i;->e:Lai/l;

    .line 7
    .line 8
    invoke-virtual {p0}, Lai/l;->b()Lzb/k0;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const-string v0, "POLLING_TAG"

    .line 13
    .line 14
    invoke-static {p0, v0}, Lzb/k0;->a(Lzb/k0;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_0
    iget-object p0, p0, Lai/i;->e:Lai/l;

    .line 21
    .line 22
    iget-object v0, p0, Lai/l;->j:Lyy0/c2;

    .line 23
    .line 24
    new-instance v1, Llc/q;

    .line 25
    .line 26
    sget-object v2, Llc/a;->c:Llc/c;

    .line 27
    .line 28
    invoke-direct {v1, v2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    const/4 v2, 0x0

    .line 35
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0}, Lai/l;->b()Lzb/k0;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    new-instance v1, La7/o;

    .line 43
    .line 44
    const/4 v3, 0x4

    .line 45
    invoke-direct {v1, p0, v2, v3}, La7/o;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 46
    .line 47
    .line 48
    const/4 p0, 0x6

    .line 49
    const-string v3, "POLLING_TAG"

    .line 50
    .line 51
    invoke-static {v0, v3, v2, v1, p0}, Lzb/k0;->c(Lzb/k0;Ljava/lang/String;Lvy0/x;Lay0/n;I)V

    .line 52
    .line 53
    .line 54
    goto :goto_0

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
