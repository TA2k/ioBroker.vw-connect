.class public Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;
.super Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;,
        Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$WithInlinedExpunction;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<K:",
        "Ljava/lang/Object;",
        "V:",
        "Ljava/lang/Object;",
        ">",
        "Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap<",
        "TK;TV;",
        "Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey<",
        "TK;>;>;"
    }
.end annotation


# static fields
.field private static final ID:Ljava/util/concurrent/atomic/AtomicLong;

.field private static final LOOKUP_KEY_CACHE:Ljava/lang/ThreadLocal;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/ThreadLocal<",
            "Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey<",
            "*>;>;"
        }
    .end annotation
.end field


# instance fields
.field private final reuseKeys:Z

.field private final thread:Ljava/lang/Thread;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$1;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$1;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->LOOKUP_KEY_CACHE:Ljava/lang/ThreadLocal;

    .line 7
    .line 8
    new-instance v0, Ljava/util/concurrent/atomic/AtomicLong;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicLong;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->ID:Ljava/util/concurrent/atomic/AtomicLong;

    .line 14
    .line 15
    return-void
.end method

.method public constructor <init>(Z)V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;

    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v0

    invoke-static {v0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->isPersistentClassLoader(Ljava/lang/ClassLoader;)Z

    move-result v0

    invoke-direct {p0, p1, v0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;-><init>(ZZ)V

    return-void
.end method

.method public constructor <init>(ZZ)V
    .locals 1

    .line 2
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    invoke-direct {p0, p1, p2, v0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;-><init>(ZZLjava/util/concurrent/ConcurrentMap;)V

    return-void
.end method

.method public constructor <init>(ZZLjava/util/concurrent/ConcurrentMap;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(ZZ",
            "Ljava/util/concurrent/ConcurrentMap<",
            "Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap$WeakKey<",
            "TK;>;TV;>;)V"
        }
    .end annotation

    .line 3
    invoke-direct {p0, p3}, Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap;-><init>(Ljava/util/concurrent/ConcurrentMap;)V

    .line 4
    iput-boolean p2, p0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->reuseKeys:Z

    if-eqz p1, :cond_0

    .line 5
    new-instance p1, Ljava/lang/Thread;

    invoke-direct {p1, p0}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    iput-object p1, p0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->thread:Ljava/lang/Thread;

    .line 6
    new-instance p0, Ljava/lang/StringBuilder;

    const-string p2, "weak-ref-cleaner-"

    invoke-direct {p0, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    sget-object p2, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->ID:Ljava/util/concurrent/atomic/AtomicLong;

    invoke-virtual {p2}, Ljava/util/concurrent/atomic/AtomicLong;->getAndIncrement()J

    move-result-wide p2

    invoke-virtual {p0, p2, p3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p1, p0}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    const/4 p0, 0x1

    .line 7
    invoke-virtual {p1, p0}, Ljava/lang/Thread;->setPriority(I)V

    .line 8
    invoke-virtual {p1, p0}, Ljava/lang/Thread;->setDaemon(Z)V

    .line 9
    invoke-virtual {p1}, Ljava/lang/Thread;->start()V

    return-void

    :cond_0
    const/4 p1, 0x0

    .line 10
    iput-object p1, p0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->thread:Ljava/lang/Thread;

    return-void
.end method

.method private static isPersistentClassLoader(Ljava/lang/ClassLoader;)Z
    .locals 2

    .line 1
    if-eqz p0, :cond_1

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    :try_start_0
    invoke-static {}, Ljava/lang/ClassLoader;->getSystemClassLoader()Ljava/lang/ClassLoader;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    if-eq p0, v1, :cond_1

    .line 9
    .line 10
    invoke-static {}, Ljava/lang/ClassLoader;->getSystemClassLoader()Ljava/lang/ClassLoader;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v1}, Ljava/lang/ClassLoader;->getParent()Ljava/lang/ClassLoader;

    .line 15
    .line 16
    .line 17
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    if-ne p0, v1, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :catchall_0
    :cond_0
    return v0

    .line 22
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 23
    return p0
.end method


# virtual methods
.method public bridge synthetic approximateSize()I
    .locals 0

    .line 1
    invoke-super {p0}, Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap;->approximateSize()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public bridge synthetic clear()V
    .locals 0

    .line 1
    invoke-super {p0}, Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap;->clear()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public bridge synthetic containsKey(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap;->containsKey(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public bridge synthetic expungeStaleEntries()V
    .locals 0

    .line 1
    invoke-super {p0}, Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap;->expungeStaleEntries()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public bridge synthetic get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public getCleanerThread()Ljava/lang/Thread;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->thread:Ljava/lang/Thread;

    .line 2
    .line 3
    return-object p0
.end method

.method public bridge synthetic getIfPresent(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap;->getIfPresent(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public getLookupKey(Ljava/lang/Object;)Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TK;)",
            "Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey<",
            "TK;>;"
        }
    .end annotation

    .line 2
    iget-boolean p0, p0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->reuseKeys:Z

    if-eqz p0, :cond_0

    .line 3
    sget-object p0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->LOOKUP_KEY_CACHE:Ljava/lang/ThreadLocal;

    invoke-virtual {p0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;

    goto :goto_0

    .line 4
    :cond_0
    new-instance p0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;

    invoke-direct {p0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;-><init>()V

    .line 5
    :goto_0
    invoke-virtual {p0, p1}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;->withValue(Ljava/lang/Object;)Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic getLookupKey(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->getLookupKey(Ljava/lang/Object;)Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic iterator()Ljava/util/Iterator;
    .locals 0

    .line 1
    invoke-super {p0}, Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public bridge synthetic put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-super {p0, p1, p2}, Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public bridge synthetic putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-super {p0, p1, p2}, Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public bridge synthetic putIfProbablyAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-super {p0, p1, p2}, Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap;->putIfProbablyAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public bridge synthetic remove(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public resetLookupKey(Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey<",
            "TK;>;)V"
        }
    .end annotation

    .line 2
    invoke-virtual {p1}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;->reset()V

    return-void
.end method

.method public bridge synthetic resetLookupKey(Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;

    invoke-virtual {p0, p1}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->resetLookupKey(Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;)V

    return-void
.end method

.method public bridge synthetic run()V
    .locals 0

    .line 1
    invoke-super {p0}, Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap;->run()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public bridge synthetic toString()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-super {p0}, Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap;->toString()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
