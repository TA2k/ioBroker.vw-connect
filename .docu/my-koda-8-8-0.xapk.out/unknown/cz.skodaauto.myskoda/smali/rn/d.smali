.class public final Lrn/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzs/d;


# static fields
.field public static final a:Lrn/d;

.field public static final b:Lzs/c;

.field public static final c:Lzs/c;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lrn/d;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lrn/d;->a:Lrn/d;

    .line 7
    .line 8
    new-instance v0, Lct/a;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, v1}, Lct/a;-><init>(I)V

    .line 12
    .line 13
    .line 14
    const-class v1, Lct/e;

    .line 15
    .line 16
    invoke-static {v1, v0}, Lp3/m;->t(Ljava/lang/Class;Lct/a;)Ljava/util/HashMap;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    new-instance v2, Lzs/c;

    .line 21
    .line 22
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    const-string v3, "logSource"

    .line 27
    .line 28
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 29
    .line 30
    .line 31
    sput-object v2, Lrn/d;->b:Lzs/c;

    .line 32
    .line 33
    new-instance v0, Lct/a;

    .line 34
    .line 35
    const/4 v2, 0x2

    .line 36
    invoke-direct {v0, v2}, Lct/a;-><init>(I)V

    .line 37
    .line 38
    .line 39
    invoke-static {v1, v0}, Lp3/m;->t(Ljava/lang/Class;Lct/a;)Ljava/util/HashMap;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    new-instance v1, Lzs/c;

    .line 44
    .line 45
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    const-string v2, "logEventDropped"

    .line 50
    .line 51
    invoke-direct {v1, v2, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 52
    .line 53
    .line 54
    sput-object v1, Lrn/d;->c:Lzs/c;

    .line 55
    .line 56
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    .line 1
    check-cast p1, Lun/f;

    .line 2
    .line 3
    check-cast p2, Lzs/e;

    .line 4
    .line 5
    sget-object p0, Lrn/d;->b:Lzs/c;

    .line 6
    .line 7
    iget-object v0, p1, Lun/f;->a:Ljava/lang/String;

    .line 8
    .line 9
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 10
    .line 11
    .line 12
    sget-object p0, Lrn/d;->c:Lzs/c;

    .line 13
    .line 14
    iget-object p1, p1, Lun/f;->b:Ljava/util/List;

    .line 15
    .line 16
    invoke-interface {p2, p0, p1}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 17
    .line 18
    .line 19
    return-void
.end method
