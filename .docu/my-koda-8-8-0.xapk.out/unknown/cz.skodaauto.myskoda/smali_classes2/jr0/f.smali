.class public final Ljr0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Ljr0/d;


# direct methods
.method public constructor <init>(Ljr0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ljr0/f;->a:Ljr0/d;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lkr0/c;)V
    .locals 1

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ljr0/f;->a:Ljr0/d;

    .line 7
    .line 8
    check-cast p0, Lhr0/a;

    .line 9
    .line 10
    iget-object p0, p0, Lhr0/a;->a:Ljava/util/concurrent/ConcurrentHashMap;

    .line 11
    .line 12
    iget-object p1, p1, Lkr0/c;->a:Ljava/lang/String;

    .line 13
    .line 14
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-virtual {p0, p1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lkr0/c;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Ljr0/f;->a(Lkr0/c;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
