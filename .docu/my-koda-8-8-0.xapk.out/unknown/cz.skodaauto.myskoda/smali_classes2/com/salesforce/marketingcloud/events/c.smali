.class public Lcom/salesforce/marketingcloud/events/c;
.super Lcom/salesforce/marketingcloud/events/EventManager;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/e;
.implements Lcom/salesforce/marketingcloud/k$f;
.implements Lcom/salesforce/marketingcloud/behaviors/b;
.implements Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventSubscriber;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field public static final r:Ljava/lang/String; = "event_gate_time_mills"

.field public static final s:Ljava/lang/String; = "event_max_display_in_session"

.field public static final t:Ljava/lang/String; = "event_min_time_sec_in_session"

.field static final u:Ljava/lang/String;

.field private static final v:Ljava/lang/String; = "$opencount"

.field private static final w:I = 0x1

.field private static final x:Ljava/util/EnumSet;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/EnumSet<",
            "Lcom/salesforce/marketingcloud/k$e;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field protected final d:Lcom/salesforce/marketingcloud/analytics/m;

.field final e:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

.field final f:Lcom/salesforce/marketingcloud/storage/h;

.field private final g:Lcom/salesforce/marketingcloud/k;

.field private final h:Lcom/salesforce/marketingcloud/behaviors/c;

.field private final i:Lcom/salesforce/marketingcloud/events/f;

.field private final j:Lcom/salesforce/marketingcloud/analytics/l;

.field private final k:Lcom/salesforce/marketingcloud/analytics/n;

.field private final l:Lcom/salesforce/marketingcloud/internal/n;

.field private final m:Ljava/util/concurrent/atomic/AtomicBoolean;

.field private final n:Landroid/content/Context;

.field protected o:Ljava/util/concurrent/CountDownLatch;

.field protected p:Lcom/salesforce/marketingcloud/config/a;

.field private q:Lcom/salesforce/marketingcloud/registration/f;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "EventManager"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/events/c;->u:Ljava/lang/String;

    .line 8
    .line 9
    sget-object v0, Lcom/salesforce/marketingcloud/k$e;->d:Lcom/salesforce/marketingcloud/k$e;

    .line 10
    .line 11
    invoke-static {v0}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;)Ljava/util/EnumSet;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lcom/salesforce/marketingcloud/events/c;->x:Ljava/util/EnumSet;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/k;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/analytics/h;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/config/a;Lcom/salesforce/marketingcloud/events/f;)V
    .locals 2

    .line 16
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/events/EventManager;-><init>()V

    .line 17
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object v0, p0, Lcom/salesforce/marketingcloud/events/c;->m:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 18
    new-instance v0, Ljava/util/concurrent/CountDownLatch;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Ljava/util/concurrent/CountDownLatch;-><init>(I)V

    iput-object v0, p0, Lcom/salesforce/marketingcloud/events/c;->o:Ljava/util/concurrent/CountDownLatch;

    .line 19
    iput-object p1, p0, Lcom/salesforce/marketingcloud/events/c;->n:Landroid/content/Context;

    .line 20
    iput-object p2, p0, Lcom/salesforce/marketingcloud/events/c;->q:Lcom/salesforce/marketingcloud/registration/f;

    .line 21
    iput-object p3, p0, Lcom/salesforce/marketingcloud/events/c;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 22
    iput-object p4, p0, Lcom/salesforce/marketingcloud/events/c;->g:Lcom/salesforce/marketingcloud/k;

    .line 23
    iput-object p5, p0, Lcom/salesforce/marketingcloud/events/c;->h:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 24
    iput-object p6, p0, Lcom/salesforce/marketingcloud/events/c;->d:Lcom/salesforce/marketingcloud/analytics/m;

    .line 25
    iput-object p6, p0, Lcom/salesforce/marketingcloud/events/c;->k:Lcom/salesforce/marketingcloud/analytics/n;

    .line 26
    iput-object p10, p0, Lcom/salesforce/marketingcloud/events/c;->i:Lcom/salesforce/marketingcloud/events/f;

    .line 27
    iput-object p7, p0, Lcom/salesforce/marketingcloud/events/c;->l:Lcom/salesforce/marketingcloud/internal/n;

    .line 28
    iput-object p8, p0, Lcom/salesforce/marketingcloud/events/c;->e:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    .line 29
    iput-object p6, p0, Lcom/salesforce/marketingcloud/events/c;->j:Lcom/salesforce/marketingcloud/analytics/l;

    .line 30
    iput-object p9, p0, Lcom/salesforce/marketingcloud/events/c;->p:Lcom/salesforce/marketingcloud/config/a;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/k;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/analytics/m;Lcom/salesforce/marketingcloud/analytics/n;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/events/f;Lcom/salesforce/marketingcloud/config/a;Lcom/salesforce/marketingcloud/analytics/l;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/events/EventManager;-><init>()V

    .line 2
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object v0, p0, Lcom/salesforce/marketingcloud/events/c;->m:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 3
    new-instance v0, Ljava/util/concurrent/CountDownLatch;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Ljava/util/concurrent/CountDownLatch;-><init>(I)V

    iput-object v0, p0, Lcom/salesforce/marketingcloud/events/c;->o:Ljava/util/concurrent/CountDownLatch;

    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/events/c;->n:Landroid/content/Context;

    .line 5
    iput-object p2, p0, Lcom/salesforce/marketingcloud/events/c;->q:Lcom/salesforce/marketingcloud/registration/f;

    .line 6
    iput-object p3, p0, Lcom/salesforce/marketingcloud/events/c;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 7
    iput-object p4, p0, Lcom/salesforce/marketingcloud/events/c;->g:Lcom/salesforce/marketingcloud/k;

    .line 8
    iput-object p5, p0, Lcom/salesforce/marketingcloud/events/c;->h:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 9
    iput-object p6, p0, Lcom/salesforce/marketingcloud/events/c;->d:Lcom/salesforce/marketingcloud/analytics/m;

    .line 10
    iput-object p7, p0, Lcom/salesforce/marketingcloud/events/c;->k:Lcom/salesforce/marketingcloud/analytics/n;

    .line 11
    iput-object p10, p0, Lcom/salesforce/marketingcloud/events/c;->i:Lcom/salesforce/marketingcloud/events/f;

    .line 12
    iput-object p8, p0, Lcom/salesforce/marketingcloud/events/c;->l:Lcom/salesforce/marketingcloud/internal/n;

    .line 13
    iput-object p9, p0, Lcom/salesforce/marketingcloud/events/c;->e:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    .line 14
    iput-object p12, p0, Lcom/salesforce/marketingcloud/events/c;->j:Lcom/salesforce/marketingcloud/analytics/l;

    .line 15
    iput-object p11, p0, Lcom/salesforce/marketingcloud/events/c;->p:Lcom/salesforce/marketingcloud/config/a;

    return-void
.end method

.method private a(Lcom/salesforce/marketingcloud/events/h;Lcom/salesforce/marketingcloud/events/Event;Ljava/util/List;)Lcom/salesforce/marketingcloud/events/predicates/f;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/events/h;",
            "Lcom/salesforce/marketingcloud/events/Event;",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/events/g;",
            ">;)",
            "Lcom/salesforce/marketingcloud/events/predicates/f;"
        }
    .end annotation

    if-eqz p3, :cond_7

    .line 25
    invoke-interface {p3}, Ljava/util/List;->size()I

    move-result v0

    if-nez v0, :cond_0

    goto/16 :goto_4

    .line 26
    :cond_0
    invoke-static {p2}, Lcom/salesforce/marketingcloud/events/d;->a(Lcom/salesforce/marketingcloud/events/Event;)Ljava/util/Map;

    move-result-object p2

    .line 27
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/events/c;->a(Lcom/salesforce/marketingcloud/events/h;)Ljava/util/Map;

    move-result-object v0

    .line 28
    invoke-interface {v0, p2}, Ljava/util/Map;->putAll(Ljava/util/Map;)V

    .line 29
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/events/h;->g()Ljava/lang/String;

    move-result-object p1

    const-string p2, "||"

    const/4 v1, 0x0

    if-eqz p1, :cond_3

    .line 30
    new-instance v2, Ljava/util/HashMap;

    invoke-interface {p3}, Ljava/util/List;->size()I

    move-result v3

    invoke-direct {v2, v3}, Ljava/util/HashMap;-><init>(I)V

    .line 31
    invoke-interface {p3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p3

    :goto_0
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lcom/salesforce/marketingcloud/events/g;

    .line 32
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/events/g;->f()I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-virtual {v2, v4, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    .line 33
    :cond_1
    new-instance p3, Ljava/util/ArrayList;

    invoke-virtual {v2}, Ljava/util/HashMap;->size()I

    move-result v3

    invoke-direct {p3, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 34
    invoke-virtual {p1, p2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-eqz v3, :cond_2

    .line 35
    const-string v3, "\\|\\|"

    invoke-virtual {p1, v3}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v3

    goto :goto_1

    .line 36
    :cond_2
    const-string v3, "&&"

    invoke-virtual {p1, v3}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v3

    .line 37
    :goto_1
    array-length v4, v3

    move v5, v1

    :goto_2
    if-ge v5, v4, :cond_5

    aget-object v6, v3, v5

    .line 38
    invoke-static {v6}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v6

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-virtual {v2, v6}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Lcom/salesforce/marketingcloud/events/g;

    invoke-direct {p0, v0, v6}, Lcom/salesforce/marketingcloud/events/c;->a(Ljava/util/Map;Lcom/salesforce/marketingcloud/events/g;)Lcom/salesforce/marketingcloud/events/predicates/f;

    move-result-object v6

    invoke-virtual {p3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v5, v5, 0x1

    goto :goto_2

    .line 39
    :cond_3
    new-instance v2, Ljava/util/ArrayList;

    invoke-interface {p3}, Ljava/util/List;->size()I

    move-result v3

    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 40
    invoke-interface {p3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p3

    :goto_3
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lcom/salesforce/marketingcloud/events/g;

    .line 41
    invoke-direct {p0, v0, v3}, Lcom/salesforce/marketingcloud/events/c;->a(Ljava/util/Map;Lcom/salesforce/marketingcloud/events/g;)Lcom/salesforce/marketingcloud/events/predicates/f;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_4
    move-object p3, v2

    :cond_5
    if-eqz p1, :cond_6

    .line 42
    invoke-virtual {p1, p2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result p0

    if-eqz p0, :cond_6

    .line 43
    new-instance p0, Lcom/salesforce/marketingcloud/events/predicates/e;

    new-array p1, v1, [Lcom/salesforce/marketingcloud/events/predicates/f;

    invoke-interface {p3, p1}, Ljava/util/List;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Lcom/salesforce/marketingcloud/events/predicates/f;

    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/events/predicates/e;-><init>([Lcom/salesforce/marketingcloud/events/predicates/f;)V

    return-object p0

    .line 44
    :cond_6
    new-instance p0, Lcom/salesforce/marketingcloud/events/predicates/a;

    new-array p1, v1, [Lcom/salesforce/marketingcloud/events/predicates/f;

    invoke-interface {p3, p1}, Ljava/util/List;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Lcom/salesforce/marketingcloud/events/predicates/f;

    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/events/predicates/a;-><init>([Lcom/salesforce/marketingcloud/events/predicates/f;)V

    return-object p0

    .line 45
    :cond_7
    :goto_4
    sget-object p0, Lcom/salesforce/marketingcloud/events/predicates/f;->b:Lcom/salesforce/marketingcloud/events/predicates/f;

    return-object p0
.end method

.method private a(Ljava/lang/Object;Lcom/salesforce/marketingcloud/events/g;)Lcom/salesforce/marketingcloud/events/predicates/f;
    .locals 1

    .line 59
    sget-object p0, Lcom/salesforce/marketingcloud/events/c$g;->a:[I

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/events/g;->j()Lcom/salesforce/marketingcloud/events/g$b;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    aget p0, p0, v0

    const/4 v0, 0x1

    if-eq p0, v0, :cond_3

    const/4 v0, 0x2

    if-eq p0, v0, :cond_2

    const/4 v0, 0x3

    if-eq p0, v0, :cond_1

    const/4 v0, 0x4

    if-eq p0, v0, :cond_0

    .line 60
    sget-object p0, Lcom/salesforce/marketingcloud/events/predicates/f;->c:Lcom/salesforce/marketingcloud/events/predicates/f;

    return-object p0

    .line 61
    :cond_0
    new-instance p0, Lcom/salesforce/marketingcloud/events/predicates/g;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/events/g;->h()Lcom/salesforce/marketingcloud/events/g$a;

    move-result-object v0

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/events/g;->i()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p0, p1, v0, p2}, Lcom/salesforce/marketingcloud/events/predicates/g;-><init>(Ljava/lang/Object;Lcom/salesforce/marketingcloud/events/g$a;Ljava/lang/Object;)V

    return-object p0

    .line 62
    :cond_1
    new-instance p0, Lcom/salesforce/marketingcloud/events/predicates/b;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/events/g;->h()Lcom/salesforce/marketingcloud/events/g$a;

    move-result-object v0

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/events/g;->i()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p0, p1, v0, p2}, Lcom/salesforce/marketingcloud/events/predicates/b;-><init>(Ljava/lang/Object;Lcom/salesforce/marketingcloud/events/g$a;Ljava/lang/Object;)V

    return-object p0

    .line 63
    :cond_2
    new-instance p0, Lcom/salesforce/marketingcloud/events/predicates/c;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/events/g;->h()Lcom/salesforce/marketingcloud/events/g$a;

    move-result-object v0

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/events/g;->i()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p0, p1, v0, p2}, Lcom/salesforce/marketingcloud/events/predicates/c;-><init>(Ljava/lang/Object;Lcom/salesforce/marketingcloud/events/g$a;Ljava/lang/Object;)V

    return-object p0

    .line 64
    :cond_3
    new-instance p0, Lcom/salesforce/marketingcloud/events/predicates/d;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/events/g;->h()Lcom/salesforce/marketingcloud/events/g$a;

    move-result-object v0

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/events/g;->i()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p0, p1, v0, p2}, Lcom/salesforce/marketingcloud/events/predicates/d;-><init>(Ljava/lang/Object;Lcom/salesforce/marketingcloud/events/g$a;Ljava/lang/Object;)V

    return-object p0
.end method

.method private a(Ljava/util/Map;Lcom/salesforce/marketingcloud/events/g;)Lcom/salesforce/marketingcloud/events/predicates/f;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/Object;",
            ">;>;",
            "Lcom/salesforce/marketingcloud/events/g;",
            ")",
            "Lcom/salesforce/marketingcloud/events/predicates/f;"
        }
    .end annotation

    if-nez p2, :cond_0

    .line 46
    sget-object p0, Lcom/salesforce/marketingcloud/events/predicates/f;->c:Lcom/salesforce/marketingcloud/events/predicates/f;

    return-object p0

    .line 47
    :cond_0
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 48
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/events/g;->g()Ljava/lang/String;

    move-result-object v1

    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/List;

    const/4 v1, 0x0

    if-eqz p1, :cond_3

    .line 49
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    move v2, v1

    :catch_0
    :cond_1
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    .line 50
    instance-of v4, v3, Ljava/util/List;

    if-eqz v4, :cond_2

    .line 51
    :try_start_0
    check-cast v3, Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_1

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    .line 52
    invoke-direct {p0, v4, p2}, Lcom/salesforce/marketingcloud/events/c;->a(Ljava/lang/Object;Lcom/salesforce/marketingcloud/events/g;)Lcom/salesforce/marketingcloud/events/predicates/f;

    move-result-object v4

    .line 53
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    add-int/lit8 v2, v2, 0x1

    goto :goto_1

    .line 54
    :cond_2
    invoke-direct {p0, v3, p2}, Lcom/salesforce/marketingcloud/events/c;->a(Ljava/lang/Object;Lcom/salesforce/marketingcloud/events/g;)Lcom/salesforce/marketingcloud/events/predicates/f;

    move-result-object v3

    .line 55
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_3
    move v2, v1

    :cond_4
    const/4 p0, 0x1

    if-le v2, p0, :cond_5

    .line 56
    new-instance p0, Lcom/salesforce/marketingcloud/events/predicates/e;

    new-array p1, v1, [Lcom/salesforce/marketingcloud/events/predicates/f;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Lcom/salesforce/marketingcloud/events/predicates/f;

    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/events/predicates/e;-><init>([Lcom/salesforce/marketingcloud/events/predicates/f;)V

    return-object p0

    :cond_5
    if-ne v2, p0, :cond_6

    .line 57
    new-instance p0, Lcom/salesforce/marketingcloud/events/predicates/a;

    new-array p1, v1, [Lcom/salesforce/marketingcloud/events/predicates/f;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Lcom/salesforce/marketingcloud/events/predicates/f;

    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/events/predicates/a;-><init>([Lcom/salesforce/marketingcloud/events/predicates/f;)V

    return-object p0

    .line 58
    :cond_6
    sget-object p0, Lcom/salesforce/marketingcloud/events/predicates/f;->c:Lcom/salesforce/marketingcloud/events/predicates/f;

    return-object p0
.end method

.method private a(Lcom/salesforce/marketingcloud/events/h;)Ljava/util/Map;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/events/h;",
            ")",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/Object;",
            ">;>;"
        }
    .end annotation

    .line 23
    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 24
    new-instance v1, Lcom/salesforce/marketingcloud/events/c$c;

    invoke-direct {v1, p0, p1}, Lcom/salesforce/marketingcloud/events/c$c;-><init>(Lcom/salesforce/marketingcloud/events/c;Lcom/salesforce/marketingcloud/events/h;)V

    const-string p0, "$opencount"

    invoke-virtual {v0, p0, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object v0
.end method

.method private a()V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/events/c;->e:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    if-eqz v0, :cond_0

    .line 2
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;->getEventManager()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;

    move-result-object v0

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->subscribe(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventSubscriber;)V

    :cond_0
    return-void
.end method

.method private a(Lorg/json/JSONObject;)V
    .locals 11

    .line 65
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    const/4 v2, 0x0

    .line 66
    :try_start_0
    const-string v3, "items"

    invoke-virtual {p1, v3}, Lorg/json/JSONObject;->getJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object p1

    .line 67
    invoke-virtual {p1}, Lorg/json/JSONArray;->length()I

    move-result v3

    .line 68
    sget-object v4, Lcom/salesforce/marketingcloud/events/c;->u:Ljava/lang/String;

    const-string v5, "%d triggers received from sync."

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    filled-new-array {v6}, [Ljava/lang/Object;

    move-result-object v6

    invoke-static {v4, v5, v6}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 69
    new-instance v4, Ljava/util/TreeSet;

    invoke-direct {v4}, Ljava/util/TreeSet;-><init>()V

    .line 70
    iget-object v5, p0, Lcom/salesforce/marketingcloud/events/c;->f:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->q()Lcom/salesforce/marketingcloud/storage/m;

    move-result-object v5
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_1

    move v6, v2

    :goto_0
    if-ge v6, v3, :cond_0

    .line 71
    :try_start_1
    new-instance v7, Lcom/salesforce/marketingcloud/events/h;

    invoke-virtual {p1, v6}, Lorg/json/JSONArray;->getJSONObject(I)Lorg/json/JSONObject;

    move-result-object v8

    invoke-direct {v7, v8}, Lcom/salesforce/marketingcloud/events/h;-><init>(Lorg/json/JSONObject;)V

    .line 72
    invoke-interface {v5, v7}, Lcom/salesforce/marketingcloud/storage/m;->a(Lcom/salesforce/marketingcloud/events/h;)V

    .line 73
    invoke-virtual {v7}, Lcom/salesforce/marketingcloud/events/h;->h()Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v4, v7}, Ljava/util/TreeSet;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    goto :goto_1

    :catch_0
    move-exception v7

    .line 74
    :try_start_2
    sget-object v8, Lcom/salesforce/marketingcloud/events/c;->u:Ljava/lang/String;

    const-string v9, "Unable to parse trigger from payload"

    new-array v10, v2, [Ljava/lang/Object;

    invoke-static {v8, v7, v9, v10}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :goto_1
    add-int/lit8 v6, v6, 0x1

    goto :goto_0

    :catch_1
    move-exception p1

    goto :goto_2

    .line 75
    :cond_0
    invoke-interface {v5, v4}, Lcom/salesforce/marketingcloud/storage/m;->b(Ljava/util/Collection;)I

    .line 76
    new-instance p1, Lorg/json/JSONObject;

    invoke-direct {p1}, Lorg/json/JSONObject;-><init>()V

    .line 77
    sget-object v3, Lcom/salesforce/marketingcloud/analytics/l$a;->d:Lcom/salesforce/marketingcloud/analytics/l$a;

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/analytics/l$a;->b()Ljava/lang/String;

    move-result-object v4

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v5

    sub-long/2addr v5, v0

    invoke-virtual {p1, v4, v5, v6}, Lorg/json/JSONObject;->put(Ljava/lang/String;J)Lorg/json/JSONObject;

    .line 78
    iget-object v0, p0, Lcom/salesforce/marketingcloud/events/c;->p:Lcom/salesforce/marketingcloud/config/a;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/config/a;->n()Z

    move-result v0

    if-eqz v0, :cond_1

    .line 79
    iget-object v0, p0, Lcom/salesforce/marketingcloud/events/c;->j:Lcom/salesforce/marketingcloud/analytics/l;

    invoke-interface {v0, v3, p1}, Lcom/salesforce/marketingcloud/analytics/l;->a(Lcom/salesforce/marketingcloud/analytics/l$a;Lorg/json/JSONObject;)V
    :try_end_2
    .catch Lorg/json/JSONException; {:try_start_2 .. :try_end_2} :catch_1

    goto :goto_3

    .line 80
    :goto_2
    sget-object v0, Lcom/salesforce/marketingcloud/events/c;->u:Ljava/lang/String;

    new-array v1, v2, [Ljava/lang/Object;

    const-string v2, "Unable to parse trigger sync payload"

    invoke-static {v0, p1, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 81
    :cond_1
    :goto_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/c;->o:Ljava/util/concurrent/CountDownLatch;

    invoke-virtual {p0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    return-void
.end method

.method private b()V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/events/c;->e:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;->getEventManager()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->unsubscribe(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventSubscriber;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/events/Event;)Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/events/Event;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/events/h;",
            ">;"
        }
    .end annotation

    .line 82
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/c;->f:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->q()Lcom/salesforce/marketingcloud/storage/m;

    move-result-object p0

    invoke-interface {p1}, Lcom/salesforce/marketingcloud/events/Event;->name()Ljava/lang/String;

    move-result-object p1

    invoke-interface {p0, p1}, Lcom/salesforce/marketingcloud/storage/m;->g(Ljava/lang/String;)Ljava/util/List;

    move-result-object p0

    return-object p0
.end method

.method public a(Lcom/salesforce/marketingcloud/events/Event;Ljava/util/List;)Ljava/util/List;
    .locals 8
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/events/Event;",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/events/h;",
            ">;)",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/events/e;",
            ">;"
        }
    .end annotation

    const/4 v0, 0x0

    if-eqz p2, :cond_3

    .line 12
    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result v1

    if-nez v1, :cond_0

    goto/16 :goto_3

    .line 13
    :cond_0
    :try_start_0
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :cond_1
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/events/h;

    .line 14
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/events/h;->k()Ljava/util/List;

    move-result-object v2

    invoke-direct {p0, v1, p1, v2}, Lcom/salesforce/marketingcloud/events/c;->a(Lcom/salesforce/marketingcloud/events/h;Lcom/salesforce/marketingcloud/events/Event;Ljava/util/List;)Lcom/salesforce/marketingcloud/events/predicates/f;

    move-result-object v2

    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/events/predicates/f;->b()Z

    move-result v2

    if-eqz v2, :cond_1

    if-nez v0, :cond_2

    .line 15
    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    move-object v0, v2

    goto :goto_0

    :catch_0
    move-exception p0

    goto :goto_2

    .line 16
    :cond_2
    :goto_0
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/events/h;->j()Ljava/util/List;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lcom/salesforce/marketingcloud/events/e;

    .line 17
    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    :try_start_1
    iget-object v4, p0, Lcom/salesforce/marketingcloud/events/c;->d:Lcom/salesforce/marketingcloud/analytics/m;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/events/h;->h()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/events/e;->e()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/events/e;->f()Ljava/lang/String;

    move-result-object v7

    .line 19
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/events/e;->d()Ljava/lang/String;

    move-result-object v3

    .line 20
    invoke-interface {v4, v5, v6, v7, v3}, Lcom/salesforce/marketingcloud/analytics/m;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_1

    :catch_1
    move-exception v3

    .line 21
    :try_start_2
    sget-object v4, Lcom/salesforce/marketingcloud/events/c;->u:Ljava/lang/String;

    const-string v5, "Failed to log analytics for trigger [%s]"

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/events/h;->h()Ljava/lang/String;

    move-result-object v6

    filled-new-array {v6}, [Ljava/lang/Object;

    move-result-object v6

    invoke-static {v4, v3, v5, v6}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_2
    .catch Ljava/lang/IllegalArgumentException; {:try_start_2 .. :try_end_2} :catch_0

    goto :goto_1

    .line 22
    :goto_2
    sget-object p1, Lcom/salesforce/marketingcloud/events/c;->u:Ljava/lang/String;

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/Object;

    const-string v1, "An outcome could not be reached with the given trigger(s) for the event."

    invoke-static {p1, p0, v1, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_3
    :goto_3
    return-object v0
.end method

.method public a(Ljava/util/List;)V
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/events/e;",
            ">;)V"
        }
    .end annotation

    .line 6
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    const/4 v0, 0x0

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/events/e;

    .line 7
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/events/e;->f()Ljava/lang/String;

    move-result-object v2

    const-string v3, "iam"

    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    if-nez v0, :cond_1

    .line 8
    new-instance v0, Ljava/util/TreeSet;

    invoke-direct {v0}, Ljava/util/TreeSet;-><init>()V

    .line 9
    :cond_1
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/events/e;->e()Ljava/lang/String;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    if-eqz v0, :cond_3

    .line 10
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/c;->i:Lcom/salesforce/marketingcloud/events/f;

    if-eqz p0, :cond_3

    .line 11
    invoke-interface {p0, v0}, Lcom/salesforce/marketingcloud/events/f;->handleOutcomes(Ljava/util/Collection;)V

    :cond_3
    return-void
.end method

.method public varargs a([Lcom/salesforce/marketingcloud/events/Event;)V
    .locals 5

    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/events/c;->m:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v0

    if-eqz v0, :cond_0

    return-void

    :cond_0
    const/4 v0, 0x0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/c;->l:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v1

    new-instance v2, Lcom/salesforce/marketingcloud/events/c$a;

    const-string v3, "trigger_event"

    new-array v4, v0, [Ljava/lang/Object;

    invoke-direct {v2, p0, v3, v4, p1}, Lcom/salesforce/marketingcloud/events/c$a;-><init>(Lcom/salesforce/marketingcloud/events/c;Ljava/lang/String;[Ljava/lang/Object;[Lcom/salesforce/marketingcloud/events/Event;)V

    invoke-interface {v1, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 5
    sget-object p1, Lcom/salesforce/marketingcloud/events/c;->u:Ljava/lang/String;

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "An error occurred while processing the event"

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public componentName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "Event"

    .line 2
    .line 3
    return-object p0
.end method

.method public componentState()Lorg/json/JSONObject;
    .locals 4

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    :try_start_0
    const-string v1, "triggers"

    .line 7
    .line 8
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/c;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 9
    .line 10
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->q()Lcom/salesforce/marketingcloud/storage/m;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/storage/m;->m()Lorg/json/JSONArray;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 19
    .line 20
    .line 21
    return-object v0

    .line 22
    :catch_0
    move-exception p0

    .line 23
    sget-object v1, Lcom/salesforce/marketingcloud/events/c;->u:Ljava/lang/String;

    .line 24
    .line 25
    const/4 v2, 0x0

    .line 26
    new-array v2, v2, [Ljava/lang/Object;

    .line 27
    .line 28
    const-string v3, "Unable to compile componentState for EventComponent"

    .line 29
    .line 30
    invoke-static {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    return-object v0
.end method

.method public controlChannelInit(I)V
    .locals 4

    .line 1
    const/16 v0, 0x1000

    .line 2
    .line 3
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/c;->m:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    invoke-virtual {v1, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 13
    .line 14
    .line 15
    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/c;->g:Lcom/salesforce/marketingcloud/k;

    .line 16
    .line 17
    sget-object v2, Lcom/salesforce/marketingcloud/events/c;->x:Ljava/util/EnumSet;

    .line 18
    .line 19
    const/4 v3, 0x0

    .line 20
    invoke-virtual {v1, v2, v3}, Lcom/salesforce/marketingcloud/k;->a(Ljava/util/EnumSet;Lcom/salesforce/marketingcloud/k$f;)V

    .line 21
    .line 22
    .line 23
    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/c;->h:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 24
    .line 25
    invoke-virtual {v1, p0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;)V

    .line 26
    .line 27
    .line 28
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->c(II)Z

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-eqz p1, :cond_0

    .line 33
    .line 34
    iget-object p1, p0, Lcom/salesforce/marketingcloud/events/c;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 35
    .line 36
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->q()Lcom/salesforce/marketingcloud/storage/m;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 41
    .line 42
    invoke-interface {p1, v0}, Lcom/salesforce/marketingcloud/storage/m;->b(Ljava/util/Collection;)I

    .line 43
    .line 44
    .line 45
    :cond_0
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/events/c;->b()V

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :cond_1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/events/c;->g:Lcom/salesforce/marketingcloud/k;

    .line 50
    .line 51
    sget-object v0, Lcom/salesforce/marketingcloud/events/c;->x:Ljava/util/EnumSet;

    .line 52
    .line 53
    invoke-virtual {p1, v0, p0}, Lcom/salesforce/marketingcloud/k;->a(Ljava/util/EnumSet;Lcom/salesforce/marketingcloud/k$f;)V

    .line 54
    .line 55
    .line 56
    iget-object p1, p0, Lcom/salesforce/marketingcloud/events/c;->h:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 57
    .line 58
    sget-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->i:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 59
    .line 60
    invoke-static {v0}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;)Ljava/util/EnumSet;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    invoke-virtual {p1, p0, v0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;Ljava/util/EnumSet;)V

    .line 65
    .line 66
    .line 67
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/events/c;->a()V

    .line 68
    .line 69
    .line 70
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/c;->m:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 71
    .line 72
    const/4 p1, 0x0

    .line 73
    invoke-virtual {p0, p1}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 74
    .line 75
    .line 76
    return-void
.end method

.method public init(Lcom/salesforce/marketingcloud/InitializationStatus$a;I)V
    .locals 0

    .line 1
    const/16 p1, 0x1000

    .line 2
    .line 3
    invoke-static {p2, p1}, Lcom/salesforce/marketingcloud/b;->b(II)Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    iget-object p1, p0, Lcom/salesforce/marketingcloud/events/c;->g:Lcom/salesforce/marketingcloud/k;

    .line 10
    .line 11
    sget-object p2, Lcom/salesforce/marketingcloud/events/c;->x:Ljava/util/EnumSet;

    .line 12
    .line 13
    invoke-virtual {p1, p2, p0}, Lcom/salesforce/marketingcloud/k;->a(Ljava/util/EnumSet;Lcom/salesforce/marketingcloud/k$f;)V

    .line 14
    .line 15
    .line 16
    iget-object p1, p0, Lcom/salesforce/marketingcloud/events/c;->h:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 17
    .line 18
    sget-object p2, Lcom/salesforce/marketingcloud/behaviors/a;->i:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 19
    .line 20
    invoke-static {p2}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;)Ljava/util/EnumSet;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    invoke-virtual {p1, p0, p2}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;Ljava/util/EnumSet;)V

    .line 25
    .line 26
    .line 27
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/events/c;->a()V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :cond_0
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/events/c;->b()V

    .line 32
    .line 33
    .line 34
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/c;->m:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 35
    .line 36
    const/4 p1, 0x1

    .line 37
    invoke-virtual {p0, p1}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public onBehavior(Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V
    .locals 3

    .line 1
    iget-object p2, p0, Lcom/salesforce/marketingcloud/events/c;->m:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    invoke-virtual {p2}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    if-nez p2, :cond_1

    .line 8
    .line 9
    sget-object p2, Lcom/salesforce/marketingcloud/behaviors/a;->i:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 10
    .line 11
    if-ne p1, p2, :cond_1

    .line 12
    .line 13
    iget-object p1, p0, Lcom/salesforce/marketingcloud/events/c;->o:Ljava/util/concurrent/CountDownLatch;

    .line 14
    .line 15
    invoke-virtual {p1}, Ljava/util/concurrent/CountDownLatch;->getCount()J

    .line 16
    .line 17
    .line 18
    move-result-wide p1

    .line 19
    const-wide/16 v0, 0x0

    .line 20
    .line 21
    cmp-long p1, p1, v0

    .line 22
    .line 23
    if-gtz p1, :cond_0

    .line 24
    .line 25
    new-instance p1, Ljava/util/concurrent/CountDownLatch;

    .line 26
    .line 27
    const/4 p2, 0x1

    .line 28
    invoke-direct {p1, p2}, Ljava/util/concurrent/CountDownLatch;-><init>(I)V

    .line 29
    .line 30
    .line 31
    iput-object p1, p0, Lcom/salesforce/marketingcloud/events/c;->o:Ljava/util/concurrent/CountDownLatch;

    .line 32
    .line 33
    :cond_0
    const/4 p1, 0x0

    .line 34
    :try_start_0
    iget-object p2, p0, Lcom/salesforce/marketingcloud/events/c;->l:Lcom/salesforce/marketingcloud/internal/n;

    .line 35
    .line 36
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    new-instance v0, Lcom/salesforce/marketingcloud/events/c$d;

    .line 41
    .line 42
    const-string v1, "app_foreground_trigger"

    .line 43
    .line 44
    new-array v2, p1, [Ljava/lang/Object;

    .line 45
    .line 46
    invoke-direct {v0, p0, v1, v2}, Lcom/salesforce/marketingcloud/events/c$d;-><init>(Lcom/salesforce/marketingcloud/events/c;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    invoke-interface {p2, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 50
    .line 51
    .line 52
    iget-object p2, p0, Lcom/salesforce/marketingcloud/events/c;->l:Lcom/salesforce/marketingcloud/internal/n;

    .line 53
    .line 54
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 55
    .line 56
    .line 57
    move-result-object p2

    .line 58
    new-instance v0, Lcom/salesforce/marketingcloud/events/c$e;

    .line 59
    .line 60
    const-string v1, "dev_stats_db_cleanup"

    .line 61
    .line 62
    new-array v2, p1, [Ljava/lang/Object;

    .line 63
    .line 64
    invoke-direct {v0, p0, v1, v2}, Lcom/salesforce/marketingcloud/events/c$e;-><init>(Lcom/salesforce/marketingcloud/events/c;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    invoke-interface {p2, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 68
    .line 69
    .line 70
    iget-object p2, p0, Lcom/salesforce/marketingcloud/events/c;->l:Lcom/salesforce/marketingcloud/internal/n;

    .line 71
    .line 72
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    new-instance v0, Lcom/salesforce/marketingcloud/events/c$f;

    .line 77
    .line 78
    const-string v1, "analytic_item_db_cleanup"

    .line 79
    .line 80
    new-array v2, p1, [Ljava/lang/Object;

    .line 81
    .line 82
    invoke-direct {v0, p0, v1, v2}, Lcom/salesforce/marketingcloud/events/c$f;-><init>(Lcom/salesforce/marketingcloud/events/c;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    invoke-interface {p2, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 86
    .line 87
    .line 88
    return-void

    .line 89
    :catch_0
    move-exception p0

    .line 90
    sget-object p2, Lcom/salesforce/marketingcloud/events/c;->u:Ljava/lang/String;

    .line 91
    .line 92
    new-array p1, p1, [Ljava/lang/Object;

    .line 93
    .line 94
    const-string v0, "An error occurred while triggering app foreground"

    .line 95
    .line 96
    invoke-static {p2, p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    :cond_1
    return-void
.end method

.method public varargs onEventPublished([Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V
    .locals 5

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/events/c;->e:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;->getIdentity()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 7
    .line 8
    .line 9
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move-object v0, v1

    .line 12
    :goto_0
    :try_start_1
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getInstance()Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    if-eqz v2, :cond_1

    .line 17
    .line 18
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getPushMessageManager()Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

    .line 19
    .line 20
    .line 21
    move-result-object v1
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 22
    :catch_0
    :cond_1
    :try_start_2
    invoke-static {p1}, Lcom/salesforce/marketingcloud/events/d;->a([Ljava/lang/Object;)[Lcom/salesforce/marketingcloud/events/Event;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-virtual {p0, v2}, Lcom/salesforce/marketingcloud/events/c;->a([Lcom/salesforce/marketingcloud/events/Event;)V

    .line 27
    .line 28
    .line 29
    new-instance v2, Lcom/salesforce/marketingcloud/analytics/e;

    .line 30
    .line 31
    iget-object v3, p0, Lcom/salesforce/marketingcloud/events/c;->q:Lcom/salesforce/marketingcloud/registration/f;

    .line 32
    .line 33
    iget-object v4, p0, Lcom/salesforce/marketingcloud/events/c;->n:Landroid/content/Context;

    .line 34
    .line 35
    invoke-static {v4}, Lcom/salesforce/marketingcloud/util/f;->b(Landroid/content/Context;)Z

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    invoke-direct {v2, v3, v1, v4, v0}, Lcom/salesforce/marketingcloud/analytics/e;-><init>(Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;ZLcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;)V

    .line 40
    .line 41
    .line 42
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/c;->k:Lcom/salesforce/marketingcloud/analytics/n;

    .line 43
    .line 44
    invoke-interface {p0, v2, p1}, Lcom/salesforce/marketingcloud/analytics/n;->a(Lcom/salesforce/marketingcloud/analytics/e;[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :catch_1
    move-exception p0

    .line 49
    sget-object p1, Lcom/salesforce/marketingcloud/events/c;->u:Ljava/lang/String;

    .line 50
    .line 51
    const/4 v0, 0x0

    .line 52
    new-array v0, v0, [Ljava/lang/Object;

    .line 53
    .line 54
    const-string v1, "Could not process events from onEventPublished()"

    .line 55
    .line 56
    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :goto_1
    return-void
.end method

.method public onSyncReceived(Lcom/salesforce/marketingcloud/k$e;Lorg/json/JSONObject;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/events/c;->m:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_2

    .line 8
    .line 9
    sget-object v0, Lcom/salesforce/marketingcloud/events/c;->x:Ljava/util/EnumSet;

    .line 10
    .line 11
    invoke-virtual {v0, p1}, Ljava/util/AbstractCollection;->contains(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const-string v0, "version"

    .line 19
    .line 20
    invoke-virtual {p2, v0}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    const/4 v1, 0x1

    .line 25
    if-eq v0, v1, :cond_1

    .line 26
    .line 27
    sget-object p0, Lcom/salesforce/marketingcloud/events/c;->u:Ljava/lang/String;

    .line 28
    .line 29
    const/4 p1, 0x0

    .line 30
    new-array p1, p1, [Ljava/lang/Object;

    .line 31
    .line 32
    const-string p2, "Unable to handle sync payload due to version mismatch"

    .line 33
    .line 34
    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :cond_1
    sget-object v0, Lcom/salesforce/marketingcloud/k$e;->d:Lcom/salesforce/marketingcloud/k$e;

    .line 39
    .line 40
    if-ne p1, v0, :cond_2

    .line 41
    .line 42
    invoke-direct {p0, p2}, Lcom/salesforce/marketingcloud/events/c;->a(Lorg/json/JSONObject;)V

    .line 43
    .line 44
    .line 45
    :cond_2
    :goto_0
    return-void
.end method

.method public tearDown(Z)V
    .locals 2

    .line 1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/events/c;->g:Lcom/salesforce/marketingcloud/k;

    .line 2
    .line 3
    sget-object v0, Lcom/salesforce/marketingcloud/events/c;->x:Ljava/util/EnumSet;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {p1, v0, v1}, Lcom/salesforce/marketingcloud/k;->a(Ljava/util/EnumSet;Lcom/salesforce/marketingcloud/k$f;)V

    .line 7
    .line 8
    .line 9
    iget-object p1, p0, Lcom/salesforce/marketingcloud/events/c;->h:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 10
    .line 11
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;)V

    .line 12
    .line 13
    .line 14
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/events/c;->b()V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public varargs track([Lcom/salesforce/marketingcloud/events/Event;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/events/c;->m:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    const/4 v0, 0x0

    .line 11
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/c;->l:Lcom/salesforce/marketingcloud/internal/n;

    .line 12
    .line 13
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    new-instance v2, Lcom/salesforce/marketingcloud/events/c$b;

    .line 18
    .line 19
    const-string v3, "trigger_event"

    .line 20
    .line 21
    new-array v4, v0, [Ljava/lang/Object;

    .line 22
    .line 23
    invoke-direct {v2, p0, v3, v4, p1}, Lcom/salesforce/marketingcloud/events/c$b;-><init>(Lcom/salesforce/marketingcloud/events/c;Ljava/lang/String;[Ljava/lang/Object;[Lcom/salesforce/marketingcloud/events/Event;)V

    .line 24
    .line 25
    .line 26
    invoke-interface {v1, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :catch_0
    move-exception p0

    .line 31
    sget-object p1, Lcom/salesforce/marketingcloud/events/c;->u:Ljava/lang/String;

    .line 32
    .line 33
    new-array v0, v0, [Ljava/lang/Object;

    .line 34
    .line 35
    const-string v1, "An error occurred while triggering track event"

    .line 36
    .line 37
    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    return-void
.end method
