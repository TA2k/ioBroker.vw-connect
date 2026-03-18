.class public final Lna/s;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:J

.field public e:Lay0/a;

.field public f:Lkotlin/jvm/internal/f0;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lna/t;

.field public i:I


# direct methods
.method public constructor <init>(Lna/t;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lna/s;->h:Lna/t;

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
    iput-object p1, p0, Lna/s;->g:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lna/s;->i:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lna/s;->i:I

    .line 9
    .line 10
    const-wide/16 v0, 0x0

    .line 11
    .line 12
    const/4 p1, 0x0

    .line 13
    iget-object v2, p0, Lna/s;->h:Lna/t;

    .line 14
    .line 15
    invoke-virtual {v2, v0, v1, p1, p0}, Lna/t;->b(JLc/d;Lrx0/c;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method
