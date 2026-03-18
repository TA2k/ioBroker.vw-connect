.class public final Lws/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic d:[Lhy0/z;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/ThreadLocal;

.field public final c:Lm6/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lkotlin/jvm/internal/z;

    .line 2
    .line 3
    const-string v1, "dataStore"

    .line 4
    .line 5
    const-string v2, "getDataStore(Landroid/content/Context;)Landroidx/datastore/core/DataStore;"

    .line 6
    .line 7
    const-class v3, Lws/c;

    .line 8
    .line 9
    invoke-direct {v0, v3, v1, v2}, Lkotlin/jvm/internal/z;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 13
    .line 14
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->property2(Lkotlin/jvm/internal/y;)Lhy0/y;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const/4 v1, 0x1

    .line 19
    new-array v1, v1, [Lhy0/z;

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    aput-object v0, v1, v2

    .line 23
    .line 24
    sput-object v1, Lws/c;->d:[Lhy0/z;

    .line 25
    .line 26
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;)V
    .locals 3

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "name"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p2, p0, Lws/c;->a:Ljava/lang/String;

    .line 15
    .line 16
    new-instance v0, Ljava/lang/ThreadLocal;

    .line 17
    .line 18
    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Lws/c;->b:Ljava/lang/ThreadLocal;

    .line 22
    .line 23
    new-instance v0, Lb3/g;

    .line 24
    .line 25
    new-instance v1, Lws/a;

    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    invoke-direct {v1, p0, v2}, Lws/a;-><init>(Lws/c;I)V

    .line 29
    .line 30
    .line 31
    invoke-direct {v0, v1}, Lb3/g;-><init>(Lay0/k;)V

    .line 32
    .line 33
    .line 34
    new-instance v1, Lws/a;

    .line 35
    .line 36
    const/4 v2, 0x1

    .line 37
    invoke-direct {v1, p0, v2}, Lws/a;-><init>(Lws/c;I)V

    .line 38
    .line 39
    .line 40
    const/16 v2, 0x8

    .line 41
    .line 42
    invoke-static {p2, v0, v1, v2}, Ljp/gd;->a(Ljava/lang/String;Lb3/g;Lws/a;I)Lp6/b;

    .line 43
    .line 44
    .line 45
    move-result-object p2

    .line 46
    sget-object v0, Lws/c;->d:[Lhy0/z;

    .line 47
    .line 48
    const/4 v1, 0x0

    .line 49
    aget-object v0, v0, v1

    .line 50
    .line 51
    invoke-virtual {p2, p1, v0}, Lp6/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    check-cast p1, Lm6/g;

    .line 56
    .line 57
    iput-object p1, p0, Lws/c;->c:Lm6/g;

    .line 58
    .line 59
    return-void
.end method


# virtual methods
.method public final a(Lay0/k;)V
    .locals 3

    .line 1
    new-instance v0, Lwp0/c;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, p0, p1, v2}, Lwp0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lpx0/h;->d:Lpx0/h;

    .line 9
    .line 10
    invoke-static {p0, v0}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lq6/b;

    .line 15
    .line 16
    return-void
.end method
