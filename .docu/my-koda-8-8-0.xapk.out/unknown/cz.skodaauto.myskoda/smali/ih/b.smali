.class public final synthetic Lih/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lih/d;


# direct methods
.method public synthetic constructor <init>(Lih/d;I)V
    .locals 0

    .line 1
    iput p2, p0, Lih/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lih/b;->e:Lih/d;

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
    iget v0, p0, Lih/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lih/b;->e:Lih/d;

    .line 7
    .line 8
    iget-object p0, p0, Lih/d;->j:Llx0/q;

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
    const-string v0, "POLLING_TAG"

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
    iget-object p0, p0, Lih/b;->e:Lih/d;

    .line 25
    .line 26
    iget-object v0, p0, Lih/d;->h:Lyy0/c2;

    .line 27
    .line 28
    new-instance v1, Llc/q;

    .line 29
    .line 30
    sget-object v2, Llc/a;->c:Llc/c;

    .line 31
    .line 32
    invoke-direct {v1, v2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    const/4 v2, 0x0

    .line 39
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    new-instance v1, Lg1/y2;

    .line 47
    .line 48
    const/16 v3, 0x18

    .line 49
    .line 50
    invoke-direct {v1, p0, v2, v3}, Lg1/y2;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 51
    .line 52
    .line 53
    const/4 p0, 0x3

    .line 54
    invoke-static {v0, v2, v2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    nop

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
