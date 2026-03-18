.class public final Lp7/e;
.super Lp7/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 6
    sget-object p1, Lp7/a;->b:Lp7/a;

    .line 7
    invoke-direct {p0, p1}, Lp7/e;-><init>(Lp7/c;)V

    return-void
.end method

.method public constructor <init>(Lp7/c;)V
    .locals 1

    const-string v0, "initialExtras"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    iget-object p1, p1, Lp7/c;->a:Ljava/util/LinkedHashMap;

    .line 2
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    invoke-direct {p0}, Lp7/c;-><init>()V

    .line 4
    iget-object p0, p0, Lp7/c;->a:Ljava/util/LinkedHashMap;

    .line 5
    invoke-interface {p0, p1}, Ljava/util/Map;->putAll(Ljava/util/Map;)V

    return-void
.end method


# virtual methods
.method public final a(Lp7/b;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lp7/c;->a:Ljava/util/LinkedHashMap;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
