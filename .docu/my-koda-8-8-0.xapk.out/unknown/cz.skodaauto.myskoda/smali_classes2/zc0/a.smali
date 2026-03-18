.class public final Lzc0/a;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lne0/e;

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lzc0/b;

.field public g:I


# direct methods
.method public constructor <init>(Lzc0/b;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lzc0/a;->f:Lzc0/b;

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
    iput-object p1, p0, Lzc0/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lzc0/a;->g:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lzc0/a;->g:I

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    const/4 v0, 0x0

    .line 12
    iget-object v1, p0, Lzc0/a;->f:Lzc0/b;

    .line 13
    .line 14
    invoke-static {v1, p1, v0, p0}, Lzc0/b;->a(Lzc0/b;Lne0/t;ZLrx0/c;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method
