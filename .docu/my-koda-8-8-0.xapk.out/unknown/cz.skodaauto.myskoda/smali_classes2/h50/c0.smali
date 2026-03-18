.class public final Lh50/c0;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A:I

.field public d:Ljava/util/List;

.field public e:Lqp0/r;

.field public f:Ljava/util/Collection;

.field public g:Ljava/util/Iterator;

.field public h:Lqp0/b0;

.field public i:Ljava/lang/Object;

.field public j:Lh50/s;

.field public k:Ljava/lang/Object;

.field public l:Ljava/lang/Object;

.field public m:Ljava/lang/Object;

.field public n:Ljava/lang/String;

.field public o:Ljava/util/Collection;

.field public p:Z

.field public q:Z

.field public r:Z

.field public s:Z

.field public t:Z

.field public u:I

.field public v:I

.field public w:I

.field public x:I

.field public synthetic y:Ljava/lang/Object;

.field public final synthetic z:Lh50/d0;


# direct methods
.method public constructor <init>(Lh50/d0;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lh50/c0;->z:Lh50/d0;

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
    iput-object p1, p0, Lh50/c0;->y:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lh50/c0;->A:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lh50/c0;->A:I

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    const/4 v0, 0x0

    .line 12
    iget-object v1, p0, Lh50/c0;->z:Lh50/d0;

    .line 13
    .line 14
    invoke-virtual {v1, p1, v0, p0}, Lh50/d0;->H(Ljava/util/List;ZLrx0/c;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method
