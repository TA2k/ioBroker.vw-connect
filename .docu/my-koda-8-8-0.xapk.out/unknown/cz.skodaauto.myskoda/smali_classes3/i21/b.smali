.class public final Li21/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Lh21/b;


# instance fields
.field public final a:Landroidx/lifecycle/c1;

.field public final b:Ljava/util/Set;

.field public final c:Ljava/util/concurrent/ConcurrentHashMap;

.field public final d:Lk21/a;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lh21/b;

    .line 2
    .line 3
    const-string v1, "_root_"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lh21/b;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Li21/b;->e:Lh21/b;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Landroidx/lifecycle/c1;)V
    .locals 8

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li21/b;->a:Landroidx/lifecycle/c1;

    .line 5
    .line 6
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 9
    .line 10
    .line 11
    invoke-static {v0}, Ljava/util/Collections;->newSetFromMap(Ljava/util/Map;)Ljava/util/Set;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, "newSetFromMap(...)"

    .line 16
    .line 17
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Li21/b;->b:Ljava/util/Set;

    .line 21
    .line 22
    new-instance v1, Ljava/util/concurrent/ConcurrentHashMap;

    .line 23
    .line 24
    invoke-direct {v1}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 25
    .line 26
    .line 27
    iput-object v1, p0, Li21/b;->c:Ljava/util/concurrent/ConcurrentHashMap;

    .line 28
    .line 29
    new-instance v2, Lk21/a;

    .line 30
    .line 31
    const/4 v5, 0x0

    .line 32
    const/16 v7, 0x8

    .line 33
    .line 34
    sget-object v3, Li21/b;->e:Lh21/b;

    .line 35
    .line 36
    const-string v4, "_root_"

    .line 37
    .line 38
    move-object v6, p1

    .line 39
    invoke-direct/range {v2 .. v7}, Lk21/a;-><init>(Lh21/a;Ljava/lang/String;Lh21/c;Landroidx/lifecycle/c1;I)V

    .line 40
    .line 41
    .line 42
    iput-object v2, p0, Li21/b;->d:Lk21/a;

    .line 43
    .line 44
    invoke-interface {v0, v3}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1, v4, v2}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    return-void
.end method
