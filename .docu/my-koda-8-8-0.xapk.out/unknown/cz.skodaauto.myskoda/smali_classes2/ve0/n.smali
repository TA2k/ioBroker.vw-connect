.class public final Lve0/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:Lyy0/i;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Z


# direct methods
.method public constructor <init>(Lyy0/i;Ljava/lang/String;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lve0/n;->d:Lyy0/i;

    .line 5
    .line 6
    iput-object p2, p0, Lve0/n;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-boolean p3, p0, Lve0/n;->f:Z

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance v0, Ln50/d0;

    .line 2
    .line 3
    iget-object v1, p0, Lve0/n;->e:Ljava/lang/String;

    .line 4
    .line 5
    iget-boolean v2, p0, Lve0/n;->f:Z

    .line 6
    .line 7
    invoke-direct {v0, p1, v1, v2}, Ln50/d0;-><init>(Lyy0/j;Ljava/lang/String;Z)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lve0/n;->d:Lyy0/i;

    .line 11
    .line 12
    invoke-interface {p0, v0, p2}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    if-ne p0, p1, :cond_0

    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0
.end method
