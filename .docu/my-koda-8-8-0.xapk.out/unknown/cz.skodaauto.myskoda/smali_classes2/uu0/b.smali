.class public final synthetic Luu0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Luu0/x;


# direct methods
.method public synthetic constructor <init>(Luu0/x;I)V
    .locals 0

    .line 1
    iput p2, p0, Luu0/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Luu0/b;->e:Luu0/x;

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
    iget v0, p0, Luu0/b;->d:I

    .line 2
    .line 3
    check-cast p1, Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    packed-switch v0, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Luu0/b;->e:Luu0/x;

    .line 12
    .line 13
    iget-object p0, p0, Luu0/x;->I:Lz90/x;

    .line 14
    .line 15
    iget-object p0, p0, Lz90/x;->a:Lz90/p;

    .line 16
    .line 17
    check-cast p0, Lx90/a;

    .line 18
    .line 19
    iget-object p0, p0, Lx90/a;->d:Lyy0/c2;

    .line 20
    .line 21
    const/4 p1, 0x0

    .line 22
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    iget-object p0, p0, Luu0/b;->e:Luu0/x;

    .line 29
    .line 30
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    new-instance v0, Luu0/e;

    .line 35
    .line 36
    const/16 v1, 0x16

    .line 37
    .line 38
    const/4 v2, 0x0

    .line 39
    invoke-direct {v0, p0, v2, v1}, Luu0/e;-><init>(Luu0/x;Lkotlin/coroutines/Continuation;I)V

    .line 40
    .line 41
    .line 42
    const/4 p0, 0x3

    .line 43
    invoke-static {p1, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
