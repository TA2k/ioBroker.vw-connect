.class public abstract Ljz0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljz0/j;


# instance fields
.field public final a:Ljz0/a;

.field public final b:Ljava/util/List;


# direct methods
.method public constructor <init>(Ljz0/a;Ljava/util/List;)V
    .locals 1

    .line 1
    const-string v0, "field"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ljz0/i;->a:Ljz0/a;

    .line 10
    .line 11
    iput-object p2, p0, Ljz0/i;->b:Ljava/util/List;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a()Lkz0/c;
    .locals 9

    .line 1
    new-instance v0, Lkz0/b;

    .line 2
    .line 3
    new-instance v1, Lio/ktor/utils/io/g0;

    .line 4
    .line 5
    iget-object v2, p0, Ljz0/i;->a:Ljz0/a;

    .line 6
    .line 7
    invoke-virtual {v2}, Ljz0/a;->a()Ljz0/r;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    const/4 v7, 0x0

    .line 12
    const/4 v8, 0x7

    .line 13
    const/4 v2, 0x1

    .line 14
    const-class v4, Ljz0/r;

    .line 15
    .line 16
    const-string v5, "getterNotNull"

    .line 17
    .line 18
    const-string v6, "getterNotNull(Ljava/lang/Object;)Ljava/lang/Object;"

    .line 19
    .line 20
    invoke-direct/range {v1 .. v8}, Lio/ktor/utils/io/g0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Ljz0/i;->b:Ljava/util/List;

    .line 24
    .line 25
    invoke-direct {v0, v1, p0}, Lkz0/b;-><init>(Lio/ktor/utils/io/g0;Ljava/util/List;)V

    .line 26
    .line 27
    .line 28
    return-object v0
.end method

.method public final b()Llz0/n;
    .locals 4

    .line 1
    new-instance v0, Llz0/n;

    .line 2
    .line 3
    new-instance v1, Llz0/g;

    .line 4
    .line 5
    new-instance v2, Llz0/b;

    .line 6
    .line 7
    iget-object p0, p0, Ljz0/i;->a:Ljz0/a;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljz0/a;->a()Ljz0/r;

    .line 10
    .line 11
    .line 12
    move-result-object v3

    .line 13
    invoke-virtual {p0}, Ljz0/a;->c()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-direct {v2, v3, p0}, Llz0/b;-><init>(Ljz0/r;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-direct {v1, p0}, Llz0/g;-><init>(Ljava/util/List;)V

    .line 25
    .line 26
    .line 27
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 32
    .line 33
    invoke-direct {v0, p0, v1}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 34
    .line 35
    .line 36
    return-object v0
.end method

.method public final c()Ljz0/a;
    .locals 0

    .line 1
    iget-object p0, p0, Ljz0/i;->a:Ljz0/a;

    .line 2
    .line 3
    return-object p0
.end method
