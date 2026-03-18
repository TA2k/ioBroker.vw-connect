.class public final Llz/o;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lmz/b;

.field public e:Lss0/k;

.field public f:Lne0/t;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Llz/q;

.field public i:I


# direct methods
.method public constructor <init>(Llz/q;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Llz/o;->h:Llz/q;

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
    iput-object p1, p0, Llz/o;->g:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Llz/o;->i:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Llz/o;->i:I

    .line 9
    .line 10
    iget-object p1, p0, Llz/o;->h:Llz/q;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-virtual {p1, v0, p0}, Llz/q;->b(Lmz/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method
