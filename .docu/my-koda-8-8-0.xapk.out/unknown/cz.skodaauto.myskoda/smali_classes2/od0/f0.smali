.class public final Lod0/f0;
.super Lrx0/c;


# instance fields
.field public synthetic d:Ljava/lang/Object;

.field public e:I

.field public final synthetic f:Lhg/s;

.field public g:Lyy0/j;

.field public h:Lod0/r;

.field public i:Ljava/util/Collection;

.field public j:Ljava/util/Iterator;

.field public k:Lod0/l;

.field public l:Ljava/util/Collection;

.field public m:Ljava/util/List;

.field public n:I

.field public o:I

.field public p:I

.field public q:I

.field public r:I


# direct methods
.method public constructor <init>(Lhg/s;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lod0/f0;->f:Lhg/s;

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
    iput-object p1, p0, Lod0/f0;->d:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lod0/f0;->e:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lod0/f0;->e:I

    .line 9
    .line 10
    iget-object p1, p0, Lod0/f0;->f:Lhg/s;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-virtual {p1, v0, p0}, Lhg/s;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method
