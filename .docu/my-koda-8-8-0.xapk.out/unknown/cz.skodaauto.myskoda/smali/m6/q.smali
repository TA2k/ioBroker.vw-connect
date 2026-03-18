.class public final Lm6/q;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lm6/w;

.field public e:Lez0/c;

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lm6/w;

.field public h:I


# direct methods
.method public constructor <init>(Lm6/w;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lm6/q;->g:Lm6/w;

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
    iput-object p1, p0, Lm6/q;->f:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lm6/q;->h:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lm6/q;->h:I

    .line 9
    .line 10
    iget-object p1, p0, Lm6/q;->g:Lm6/w;

    .line 11
    .line 12
    invoke-static {p1, p0}, Lm6/w;->d(Lm6/w;Lrx0/c;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method
