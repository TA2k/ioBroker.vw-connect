.class public final Lp3/g0;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lvy0/x1;

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lp3/i0;

.field public g:I


# direct methods
.method public constructor <init>(Lp3/i0;Lrx0/a;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lp3/g0;->f:Lp3/i0;

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
    .locals 3

    .line 1
    iput-object p1, p0, Lp3/g0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lp3/g0;->g:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lp3/g0;->g:I

    .line 9
    .line 10
    const-wide/16 v0, 0x0

    .line 11
    .line 12
    const/4 p1, 0x0

    .line 13
    iget-object v2, p0, Lp3/g0;->f:Lp3/i0;

    .line 14
    .line 15
    invoke-virtual {v2, v0, v1, p1, p0}, Lp3/i0;->g(JLay0/n;Lrx0/a;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method
