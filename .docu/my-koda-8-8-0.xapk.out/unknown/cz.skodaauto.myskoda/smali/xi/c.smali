.class public final Lxi/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/v1;


# static fields
.field public static final c:Landroidx/lifecycle/m0;


# instance fields
.field public final a:Lyy0/v1;

.field public final b:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Landroidx/lifecycle/m0;->k:Landroidx/lifecycle/m0;

    .line 2
    .line 3
    sput-object v0, Lxi/c;->c:Landroidx/lifecycle/m0;

    .line 4
    .line 5
    return-void
.end method

.method public constructor <init>(Lyy0/v1;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxi/c;->a:Lyy0/v1;

    .line 5
    .line 6
    iput-object p2, p0, Lxi/c;->b:Ljava/lang/String;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lzy0/w;)Lyy0/i;
    .locals 4

    .line 1
    sget-object v0, Lxi/c;->c:Landroidx/lifecycle/m0;

    .line 2
    .line 3
    iget-object v0, v0, Landroidx/lifecycle/m0;->i:Landroidx/lifecycle/z;

    .line 4
    .line 5
    new-instance v1, Lwp0/c;

    .line 6
    .line 7
    const/4 v2, 0x7

    .line 8
    const/4 v3, 0x0

    .line 9
    invoke-direct {v1, v0, v3, v2}, Lwp0/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 10
    .line 11
    .line 12
    invoke-static {v1}, Lyy0/u;->h(Lay0/n;)Lyy0/c;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-static {v0}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    new-instance v1, Lrz/k;

    .line 21
    .line 22
    const/16 v2, 0x12

    .line 23
    .line 24
    invoke-direct {v1, v0, v2}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 25
    .line 26
    .line 27
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    new-instance v1, Lo20/c;

    .line 32
    .line 33
    const/16 v2, 0x16

    .line 34
    .line 35
    invoke-direct {v1, v2, p0, p1, v3}, Lo20/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 36
    .line 37
    .line 38
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-static {p0}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0
.end method
