.class public final Lo20/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# static fields
.field public static final e:Lne0/e;


# instance fields
.field public final a:Lm20/j;

.field public final b:Lo20/a;

.field public final c:Lgb0/y;

.field public final d:Lkf0/b0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lne0/e;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lo20/d;->e:Lne0/e;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lm20/j;Lo20/a;Lgb0/y;Lkf0/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo20/d;->a:Lm20/j;

    .line 5
    .line 6
    iput-object p2, p0, Lo20/d;->b:Lo20/a;

    .line 7
    .line 8
    iput-object p3, p0, Lo20/d;->c:Lgb0/y;

    .line 9
    .line 10
    iput-object p4, p0, Lo20/d;->d:Lkf0/b0;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lo20/d;->d:Lkf0/b0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lkf0/b0;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    new-instance v1, Lo20/c;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, 0x0

    .line 13
    iget-object v4, p0, Lo20/d;->a:Lm20/j;

    .line 14
    .line 15
    invoke-direct {v1, v3, p0, v4, v2}, Lo20/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 16
    .line 17
    .line 18
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-static {p0}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method
