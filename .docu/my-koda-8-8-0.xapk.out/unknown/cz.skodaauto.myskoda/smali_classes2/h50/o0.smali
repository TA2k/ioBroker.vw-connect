.class public final Lh50/o0;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lqp0/b0;

.field public e:Lij0/a;

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lh50/s0;

.field public h:I


# direct methods
.method public constructor <init>(Lh50/s0;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lh50/o0;->g:Lh50/s0;

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
    .locals 2

    .line 1
    iput-object p1, p0, Lh50/o0;->f:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lh50/o0;->h:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lh50/o0;->h:I

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    const/4 v0, 0x0

    .line 12
    iget-object v1, p0, Lh50/o0;->g:Lh50/s0;

    .line 13
    .line 14
    invoke-virtual {v1, p1, v0, p0}, Lh50/s0;->l(Lqp0/b0;ILrx0/c;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method
