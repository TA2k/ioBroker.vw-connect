.class public final Li70/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk70/v;
.implements Lme0/b;


# instance fields
.field public a:Ll70/d;

.field public b:Ll70/h;

.field public c:Z

.field public d:Ljava/lang/Integer;

.field public e:Ll70/a0;

.field public final f:Ljava/util/LinkedHashMap;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x1

    .line 5
    iput-boolean v0, p0, Li70/b;->c:Z

    .line 6
    .line 7
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 8
    .line 9
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Li70/b;->f:Ljava/util/LinkedHashMap;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p1, p0, Li70/b;->f:Ljava/util/LinkedHashMap;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/util/LinkedHashMap;->clear()V

    .line 4
    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    iput-object p1, p0, Li70/b;->a:Ll70/d;

    .line 8
    .line 9
    iput-object p1, p0, Li70/b;->b:Ll70/h;

    .line 10
    .line 11
    iput-object p1, p0, Li70/b;->d:Ljava/lang/Integer;

    .line 12
    .line 13
    iput-object p1, p0, Li70/b;->e:Ll70/a0;

    .line 14
    .line 15
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    return-object p0
.end method

.method public final b(Ll70/h;)Li70/a;
    .locals 1

    .line 1
    iget-object p0, p0, Li70/b;->f:Ljava/util/LinkedHashMap;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Li70/a;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    new-instance v0, Li70/a;

    .line 12
    .line 13
    invoke-direct {v0}, Li70/a;-><init>()V

    .line 14
    .line 15
    .line 16
    invoke-interface {p0, p1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    :cond_0
    return-object v0
.end method
