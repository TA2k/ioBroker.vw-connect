.class public final synthetic Lh70/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvy0/b0;

.field public final synthetic f:Lg70/j;


# direct methods
.method public synthetic constructor <init>(Lvy0/b0;Lg70/j;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh70/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh70/k;->e:Lvy0/b0;

    .line 4
    .line 5
    iput-object p2, p0, Lh70/k;->f:Lg70/j;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lh70/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lal0/m0;

    .line 7
    .line 8
    const/4 v1, 0x2

    .line 9
    const/16 v2, 0xa

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    invoke-direct {v0, v1, v3, v2}, Lal0/m0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 13
    .line 14
    .line 15
    const/4 v1, 0x3

    .line 16
    iget-object v2, p0, Lh70/k;->e:Lvy0/b0;

    .line 17
    .line 18
    invoke-static {v2, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lh70/k;->f:Lg70/j;

    .line 22
    .line 23
    iget-object p0, p0, Lg70/j;->n:Lcf0/h;

    .line 24
    .line 25
    const/4 v0, 0x1

    .line 26
    iget-object p0, p0, Lcf0/h;->a:Laf0/a;

    .line 27
    .line 28
    iput-boolean v0, p0, Laf0/a;->a:Z

    .line 29
    .line 30
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_0
    new-instance v0, Lal0/m0;

    .line 34
    .line 35
    const/4 v1, 0x2

    .line 36
    const/16 v2, 0x9

    .line 37
    .line 38
    const/4 v3, 0x0

    .line 39
    invoke-direct {v0, v1, v3, v2}, Lal0/m0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 40
    .line 41
    .line 42
    iget-object v1, p0, Lh70/k;->e:Lvy0/b0;

    .line 43
    .line 44
    const/4 v2, 0x3

    .line 45
    invoke-static {v1, v3, v3, v0, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Lh70/k;->f:Lg70/j;

    .line 49
    .line 50
    iget-object v0, p0, Lg70/j;->n:Lcf0/h;

    .line 51
    .line 52
    const/4 v1, 0x0

    .line 53
    iget-object v0, v0, Lcf0/h;->a:Laf0/a;

    .line 54
    .line 55
    iput-boolean v1, v0, Laf0/a;->a:Z

    .line 56
    .line 57
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    new-instance v1, Lg70/h;

    .line 62
    .line 63
    const/4 v4, 0x1

    .line 64
    invoke-direct {v1, p0, v3, v4}, Lg70/h;-><init>(Lg70/j;Lkotlin/coroutines/Continuation;I)V

    .line 65
    .line 66
    .line 67
    invoke-static {v0, v3, v3, v1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 68
    .line 69
    .line 70
    goto :goto_0

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
