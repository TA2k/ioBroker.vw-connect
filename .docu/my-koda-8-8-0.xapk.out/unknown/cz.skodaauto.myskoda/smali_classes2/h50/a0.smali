.class public final Lh50/a0;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lqp0/o;

.field public e:Ljava/util/Collection;

.field public f:Ljava/util/Iterator;

.field public g:Ldh0/a;

.field public h:Lh50/d0;

.field public i:I

.field public j:I

.field public k:I

.field public synthetic l:Ljava/lang/Object;

.field public final synthetic m:Lh50/d0;

.field public n:I


# direct methods
.method public constructor <init>(Lh50/d0;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lh50/a0;->m:Lh50/d0;

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
    iput-object p1, p0, Lh50/a0;->l:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lh50/a0;->n:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lh50/a0;->n:I

    .line 9
    .line 10
    iget-object p1, p0, Lh50/a0;->m:Lh50/d0;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-virtual {p1, v0, p0}, Lh50/d0;->B(Lqp0/o;Lrx0/c;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method
