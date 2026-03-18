.class public final Lm6/u;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lkotlin/jvm/internal/d0;

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lm6/w;

.field public g:I


# direct methods
.method public constructor <init>(Lm6/w;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lm6/u;->f:Lm6/w;

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
    iput-object p1, p0, Lm6/u;->e:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lm6/u;->g:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lm6/u;->g:I

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    const/4 v0, 0x0

    .line 12
    iget-object v1, p0, Lm6/u;->f:Lm6/w;

    .line 13
    .line 14
    invoke-virtual {v1, p1, v0, p0}, Lm6/w;->j(Ljava/lang/Object;ZLrx0/c;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method
