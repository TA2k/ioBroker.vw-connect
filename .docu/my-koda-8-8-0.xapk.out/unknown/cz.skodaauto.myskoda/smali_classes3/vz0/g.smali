.class public final Lvz0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lsz0/g;


# static fields
.field public static final b:Lvz0/g;

.field public static final c:Ljava/lang/String;


# instance fields
.field public final synthetic a:Luz0/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lvz0/g;

    .line 2
    .line 3
    invoke-direct {v0}, Lvz0/g;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lvz0/g;->b:Lvz0/g;

    .line 7
    .line 8
    const-string v0, "kotlinx.serialization.json.JsonArray"

    .line 9
    .line 10
    sput-object v0, Lvz0/g;->c:Ljava/lang/String;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lvz0/p;->a:Lvz0/p;

    .line 5
    .line 6
    invoke-static {v0}, Lkp/u6;->a(Lqz0/a;)Luz0/d;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iget-object v0, v0, Luz0/d;->c:Luz0/n0;

    .line 11
    .line 12
    check-cast v0, Luz0/c;

    .line 13
    .line 14
    iput-object v0, p0, Lvz0/g;->a:Luz0/c;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final b()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lvz0/g;->a:Luz0/c;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    return p0
.end method

.method public final c(Ljava/lang/String;)I
    .locals 1

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lvz0/g;->a:Luz0/c;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Luz0/n0;->c(Ljava/lang/String;)I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final d()I
    .locals 0

    .line 1
    iget-object p0, p0, Lvz0/g;->a:Luz0/c;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    return p0
.end method

.method public final e(I)Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lvz0/g;->a:Luz0/c;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public final f(I)Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lvz0/g;->a:Luz0/c;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Luz0/n0;->f(I)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 7
    .line 8
    return-object p0
.end method

.method public final g(I)Lsz0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lvz0/g;->a:Luz0/c;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Luz0/n0;->g(I)Lsz0/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getAnnotations()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lvz0/g;->a:Luz0/c;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 7
    .line 8
    return-object p0
.end method

.method public final getKind()Lkp/y8;
    .locals 0

    .line 1
    iget-object p0, p0, Lvz0/g;->a:Luz0/c;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    sget-object p0, Lsz0/k;->c:Lsz0/k;

    .line 7
    .line 8
    return-object p0
.end method

.method public final h()Ljava/lang/String;
    .locals 0

    .line 1
    sget-object p0, Lvz0/g;->c:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final i(I)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lvz0/g;->a:Luz0/c;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Luz0/n0;->i(I)Z

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    return p0
.end method

.method public final isInline()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lvz0/g;->a:Luz0/c;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    return p0
.end method
