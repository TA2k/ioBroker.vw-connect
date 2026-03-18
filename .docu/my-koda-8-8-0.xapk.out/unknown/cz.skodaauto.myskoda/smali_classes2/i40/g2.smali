.class public final synthetic Li40/g2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvy0/b0;

.field public final synthetic f:Lxf0/d2;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lvy0/b0;Lxf0/d2;Lay0/k;I)V
    .locals 0

    .line 1
    iput p4, p0, Li40/g2;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li40/g2;->e:Lvy0/b0;

    .line 4
    .line 5
    iput-object p2, p0, Li40/g2;->f:Lxf0/d2;

    .line 6
    .line 7
    iput-object p3, p0, Li40/g2;->g:Lay0/k;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Li40/g2;->d:I

    .line 2
    .line 3
    check-cast p1, Ljava/lang/Integer;

    .line 4
    .line 5
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 6
    .line 7
    .line 8
    move-result v3

    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    new-instance v0, Lh90/b;

    .line 13
    .line 14
    const/4 v5, 0x2

    .line 15
    iget-object v1, p0, Li40/g2;->f:Lxf0/d2;

    .line 16
    .line 17
    iget-object v2, p0, Li40/g2;->g:Lay0/k;

    .line 18
    .line 19
    const/4 v4, 0x0

    .line 20
    invoke-direct/range {v0 .. v5}, Lh90/b;-><init>(Lxf0/d2;Lay0/k;ILkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    const/4 p1, 0x3

    .line 24
    iget-object p0, p0, Li40/g2;->e:Lvy0/b0;

    .line 25
    .line 26
    invoke-static {p0, v4, v4, v0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 27
    .line 28
    .line 29
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    return-object p0

    .line 32
    :pswitch_0
    new-instance v0, Lh90/b;

    .line 33
    .line 34
    const/4 v5, 0x1

    .line 35
    iget-object v1, p0, Li40/g2;->f:Lxf0/d2;

    .line 36
    .line 37
    iget-object v2, p0, Li40/g2;->g:Lay0/k;

    .line 38
    .line 39
    const/4 v4, 0x0

    .line 40
    invoke-direct/range {v0 .. v5}, Lh90/b;-><init>(Lxf0/d2;Lay0/k;ILkotlin/coroutines/Continuation;I)V

    .line 41
    .line 42
    .line 43
    const/4 p1, 0x3

    .line 44
    iget-object p0, p0, Li40/g2;->e:Lvy0/b0;

    .line 45
    .line 46
    invoke-static {p0, v4, v4, v0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
