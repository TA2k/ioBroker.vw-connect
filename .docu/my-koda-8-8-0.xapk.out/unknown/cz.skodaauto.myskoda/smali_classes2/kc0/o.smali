.class public final Lkc0/o;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public synthetic d:Ljava/lang/Object;

.field public final synthetic e:Lkc0/p;

.field public f:I


# direct methods
.method public constructor <init>(Lkc0/p;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lkc0/o;->e:Lkc0/p;

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
    iput-object p1, p0, Lkc0/o;->d:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lkc0/o;->f:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lkc0/o;->f:I

    .line 9
    .line 10
    iget-object p1, p0, Lkc0/o;->e:Lkc0/p;

    .line 11
    .line 12
    invoke-virtual {p1, p0}, Lkc0/p;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method
