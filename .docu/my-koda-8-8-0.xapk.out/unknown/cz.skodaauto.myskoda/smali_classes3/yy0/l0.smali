.class public final Lyy0/l0;
.super Lrx0/c;


# instance fields
.field public d:Ly70/c0;

.field public synthetic e:Ljava/lang/Object;

.field public f:I

.field public final synthetic g:Ly70/c0;

.field public h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ly70/c0;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lyy0/l0;->g:Ly70/c0;

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
    iput-object p1, p0, Lyy0/l0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lyy0/l0;->f:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lyy0/l0;->f:I

    .line 9
    .line 10
    iget-object p1, p0, Lyy0/l0;->g:Ly70/c0;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-virtual {p1, v0, p0}, Ly70/c0;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method
