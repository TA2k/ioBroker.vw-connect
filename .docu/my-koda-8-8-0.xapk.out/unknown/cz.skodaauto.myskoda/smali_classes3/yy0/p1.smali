.class public final Lyy0/p1;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lyy0/q1;

.field public e:Lyy0/j;

.field public f:Lyy0/r1;

.field public g:Lvy0/i1;

.field public synthetic h:Ljava/lang/Object;

.field public final synthetic i:Lyy0/q1;

.field public j:I


# direct methods
.method public constructor <init>(Lyy0/q1;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lyy0/p1;->i:Lyy0/q1;

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
    iput-object p1, p0, Lyy0/p1;->h:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lyy0/p1;->j:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lyy0/p1;->j:I

    .line 9
    .line 10
    iget-object p1, p0, Lyy0/p1;->i:Lyy0/q1;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-static {p1, v0, p0}, Lyy0/q1;->k(Lyy0/q1;Lyy0/j;Lkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    return-object p0
.end method
