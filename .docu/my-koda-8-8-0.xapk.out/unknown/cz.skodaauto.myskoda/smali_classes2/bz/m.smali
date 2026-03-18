.class public final Lbz/m;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lqp0/o;

.field public e:Lqp0/o;

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lbz/n;

.field public h:I


# direct methods
.method public constructor <init>(Lbz/n;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lbz/m;->g:Lbz/n;

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
    iput-object p1, p0, Lbz/m;->f:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lbz/m;->h:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lbz/m;->h:I

    .line 9
    .line 10
    iget-object p1, p0, Lbz/m;->g:Lbz/n;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-static {p1, v0, p0}, Lbz/n;->h(Lbz/n;Lqp0/o;Lrx0/c;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method
