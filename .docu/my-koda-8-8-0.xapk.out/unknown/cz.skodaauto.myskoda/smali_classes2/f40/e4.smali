.class public final Lf40/e4;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lf40/d4;

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lf40/f4;

.field public g:I


# direct methods
.method public constructor <init>(Lf40/f4;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lf40/e4;->f:Lf40/f4;

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
    .locals 1

    .line 1
    iput-object p1, p0, Lf40/e4;->e:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lf40/e4;->g:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lf40/e4;->g:I

    .line 9
    .line 10
    iget-object p1, p0, Lf40/e4;->f:Lf40/f4;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-virtual {p1, v0, p0}, Lf40/f4;->b(Lf40/d4;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method
