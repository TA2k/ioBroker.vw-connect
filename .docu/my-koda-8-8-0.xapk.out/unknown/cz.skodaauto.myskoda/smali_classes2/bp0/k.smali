.class public final Lbp0/k;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Landroidx/core/app/x;

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lbp0/l;

.field public g:I


# direct methods
.method public constructor <init>(Lbp0/l;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lbp0/k;->f:Lbp0/l;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iput-object p1, p0, Lbp0/k;->e:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lbp0/k;->g:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lbp0/k;->g:I

    .line 9
    .line 10
    const/4 v4, 0x0

    .line 11
    const/4 v5, 0x0

    .line 12
    iget-object v0, p0, Lbp0/k;->f:Lbp0/l;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    const/4 v2, 0x0

    .line 16
    const/4 v3, 0x0

    .line 17
    move-object v6, p0

    .line 18
    invoke-virtual/range {v0 .. v6}, Lbp0/l;->b(Landroid/content/Context;Lap0/c;ILap0/a;Landroidx/core/app/x;Lrx0/c;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
