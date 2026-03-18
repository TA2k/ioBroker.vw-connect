.class public final Lkn/h;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lvy0/b0;

.field public final synthetic h:Lkn/c0;


# direct methods
.method public constructor <init>(Lkn/c0;Lvy0/b0;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lkn/h;->f:I

    .line 1
    iput-object p1, p0, Lkn/h;->h:Lkn/c0;

    iput-object p2, p0, Lkn/h;->g:Lvy0/b0;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Lvy0/b0;Lkn/c0;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lkn/h;->f:I

    .line 2
    iput-object p1, p0, Lkn/h;->g:Lvy0/b0;

    iput-object p2, p0, Lkn/h;->h:Lkn/c0;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lkn/h;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Number;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    new-instance v0, Li2/f;

    .line 13
    .line 14
    iget-object v1, p0, Lkn/h;->h:Lkn/c0;

    .line 15
    .line 16
    const/4 v2, 0x2

    .line 17
    const/4 v3, 0x0

    .line 18
    invoke-direct {v0, v1, p1, v3, v2}, Li2/f;-><init>(Ljava/lang/Object;FLkotlin/coroutines/Continuation;I)V

    .line 19
    .line 20
    .line 21
    const/4 p1, 0x3

    .line 22
    iget-object p0, p0, Lkn/h;->g:Lvy0/b0;

    .line 23
    .line 24
    invoke-static {p0, v3, v3, v0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 25
    .line 26
    .line 27
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_0
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 31
    .line 32
    const-string v0, "$this$DisposableEffect"

    .line 33
    .line 34
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    new-instance p1, Laa/t;

    .line 38
    .line 39
    const/16 v0, 0x9

    .line 40
    .line 41
    iget-object v1, p0, Lkn/h;->h:Lkn/c0;

    .line 42
    .line 43
    iget-object p0, p0, Lkn/h;->g:Lvy0/b0;

    .line 44
    .line 45
    invoke-direct {p1, v0, v1, p0}, Laa/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    return-object p1

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
