.class public final Lcom/salesforce/marketingcloud/util/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/util/d$d;,
        Lcom/salesforce/marketingcloud/util/d$c;,
        Lcom/salesforce/marketingcloud/util/d$e;
    }
.end annotation


# static fields
.field private static final A:Ljava/lang/String; = "READ"

.field static final o:Ljava/lang/String; = "journal"

.field static final p:Ljava/lang/String; = "journal.tmp"

.field static final q:Ljava/lang/String; = "journal.bkp"

.field static final r:Ljava/lang/String; = "libcore.io.DiskLruCache"

.field static final s:Ljava/lang/String; = "1"

.field static final t:J = -0x1L

.field static final u:Ljava/lang/String; = "[a-z0-9_-]{1,120}"

.field static final v:Ljava/util/regex/Pattern;

.field static final w:Ljava/io/OutputStream;

.field private static final x:Ljava/lang/String; = "CLEAN"

.field private static final y:Ljava/lang/String; = "DIRTY"

.field private static final z:Ljava/lang/String; = "REMOVE"


# instance fields
.field final a:Ljava/util/concurrent/ThreadPoolExecutor;

.field final b:Ljava/io/File;

.field final c:I

.field private final d:Ljava/io/File;

.field private final e:Ljava/io/File;

.field private final f:Ljava/io/File;

.field private final g:I

.field private final h:Ljava/util/LinkedHashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/LinkedHashMap<",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/util/d$d;",
            ">;"
        }
    .end annotation
.end field

.field i:Ljava/io/Writer;

.field j:I

.field private k:J

.field private l:J

.field private m:J

.field private final n:Ljava/util/concurrent/Callable;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/Callable<",
            "Ljava/lang/Void;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "[a-z0-9_-]{1,120}"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/util/d;->v:Ljava/util/regex/Pattern;

    .line 8
    .line 9
    new-instance v0, Lcom/salesforce/marketingcloud/util/d$a;

    .line 10
    .line 11
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/util/d$a;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/util/d;->w:Ljava/io/OutputStream;

    .line 15
    .line 16
    return-void
.end method

.method private constructor <init>(Ljava/io/File;IIJ)V
    .locals 7

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/ThreadPoolExecutor;

    .line 5
    .line 6
    sget-object v5, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 7
    .line 8
    new-instance v6, Ljava/util/concurrent/LinkedBlockingQueue;

    .line 9
    .line 10
    invoke-direct {v6}, Ljava/util/concurrent/LinkedBlockingQueue;-><init>()V

    .line 11
    .line 12
    .line 13
    const/4 v2, 0x1

    .line 14
    const-wide/16 v3, 0x3c

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    invoke-direct/range {v0 .. v6}, Ljava/util/concurrent/ThreadPoolExecutor;-><init>(IIJLjava/util/concurrent/TimeUnit;Ljava/util/concurrent/BlockingQueue;)V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->a:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 21
    .line 22
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 23
    .line 24
    const/high16 v1, 0x3f400000    # 0.75f

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    invoke-direct {v0, v3, v1, v2}, Ljava/util/LinkedHashMap;-><init>(IFZ)V

    .line 28
    .line 29
    .line 30
    iput-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->h:Ljava/util/LinkedHashMap;

    .line 31
    .line 32
    new-instance v0, Lcom/salesforce/marketingcloud/util/d$b;

    .line 33
    .line 34
    invoke-direct {v0, p0}, Lcom/salesforce/marketingcloud/util/d$b;-><init>(Lcom/salesforce/marketingcloud/util/d;)V

    .line 35
    .line 36
    .line 37
    iput-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->n:Ljava/util/concurrent/Callable;

    .line 38
    .line 39
    iput-object p1, p0, Lcom/salesforce/marketingcloud/util/d;->b:Ljava/io/File;

    .line 40
    .line 41
    iput p2, p0, Lcom/salesforce/marketingcloud/util/d;->g:I

    .line 42
    .line 43
    new-instance p2, Ljava/io/File;

    .line 44
    .line 45
    const-string v0, "journal"

    .line 46
    .line 47
    invoke-direct {p2, p1, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    iput-object p2, p0, Lcom/salesforce/marketingcloud/util/d;->d:Ljava/io/File;

    .line 51
    .line 52
    new-instance p2, Ljava/io/File;

    .line 53
    .line 54
    const-string v0, "journal.tmp"

    .line 55
    .line 56
    invoke-direct {p2, p1, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    iput-object p2, p0, Lcom/salesforce/marketingcloud/util/d;->e:Ljava/io/File;

    .line 60
    .line 61
    new-instance p2, Ljava/io/File;

    .line 62
    .line 63
    const-string v0, "journal.bkp"

    .line 64
    .line 65
    invoke-direct {p2, p1, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    iput-object p2, p0, Lcom/salesforce/marketingcloud/util/d;->f:Ljava/io/File;

    .line 69
    .line 70
    iput p3, p0, Lcom/salesforce/marketingcloud/util/d;->c:I

    .line 71
    .line 72
    iput-wide p4, p0, Lcom/salesforce/marketingcloud/util/d;->k:J

    .line 73
    .line 74
    return-void
.end method

.method public static a(Ljava/io/File;IIJ)Lcom/salesforce/marketingcloud/util/d;
    .locals 10

    const-wide/16 v0, 0x0

    cmp-long v0, p3, v0

    if-lez v0, :cond_4

    if-lez p2, :cond_3

    .line 1
    new-instance v0, Ljava/io/File;

    const-string v1, "journal.bkp"

    invoke-direct {v0, p0, v1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 2
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    move-result v1

    if-eqz v1, :cond_1

    .line 3
    new-instance v1, Ljava/io/File;

    const-string v2, "journal"

    invoke-direct {v1, p0, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 4
    invoke-virtual {v1}, Ljava/io/File;->exists()Z

    move-result v2

    if-eqz v2, :cond_0

    .line 5
    invoke-virtual {v0}, Ljava/io/File;->delete()Z

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    .line 6
    invoke-static {v0, v1, v2}, Lcom/salesforce/marketingcloud/util/d;->a(Ljava/io/File;Ljava/io/File;Z)V

    .line 7
    :cond_1
    :goto_0
    new-instance v3, Lcom/salesforce/marketingcloud/util/d;

    move-object v4, p0

    move v5, p1

    move v6, p2

    move-wide v7, p3

    invoke-direct/range {v3 .. v8}, Lcom/salesforce/marketingcloud/util/d;-><init>(Ljava/io/File;IIJ)V

    .line 8
    iget-object p0, v3, Lcom/salesforce/marketingcloud/util/d;->d:Ljava/io/File;

    invoke-virtual {p0}, Ljava/io/File;->exists()Z

    move-result p0

    if-eqz p0, :cond_2

    .line 9
    :try_start_0
    invoke-direct {v3}, Lcom/salesforce/marketingcloud/util/d;->i()V

    .line 10
    invoke-direct {v3}, Lcom/salesforce/marketingcloud/util/d;->h()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v3

    :catch_0
    move-exception v0

    move-object p0, v0

    .line 11
    filled-new-array {v4}, [Ljava/lang/Object;

    move-result-object p1

    const-string p2, "DiskLruCache"

    const-string p3, "DiskLruCache %s is corrupt, removing."

    invoke-static {p2, p0, p3, p1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 12
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/util/d;->b()V

    .line 13
    :cond_2
    invoke-virtual {v4}, Ljava/io/File;->mkdirs()Z

    move-wide v8, v7

    move v7, v6

    move v6, v5

    move-object v5, v4

    .line 14
    new-instance v4, Lcom/salesforce/marketingcloud/util/d;

    invoke-direct/range {v4 .. v9}, Lcom/salesforce/marketingcloud/util/d;-><init>(Ljava/io/File;IIJ)V

    .line 15
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/util/d;->j()V

    return-object v4

    .line 16
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "valueCount <= 0"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 17
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "maxSize <= 0"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static a(Ljava/io/InputStream;)Ljava/lang/String;
    .locals 2

    .line 23
    new-instance v0, Ljava/io/InputStreamReader;

    sget-object v1, Lcom/salesforce/marketingcloud/util/e;->c:Ljava/nio/charset/Charset;

    invoke-direct {v0, p0, v1}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;Ljava/nio/charset/Charset;)V

    invoke-static {v0}, Lcom/salesforce/marketingcloud/util/e;->a(Ljava/io/Reader;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method private a()V
    .locals 1

    .line 69
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/d;->i:Ljava/io/Writer;

    if-eqz p0, :cond_0

    return-void

    .line 70
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string v0, "cache is closed"

    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method private static a(Ljava/io/File;)V
    .locals 1

    .line 18
    invoke-virtual {p0}, Ljava/io/File;->exists()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p0}, Ljava/io/File;->delete()Z

    move-result p0

    if-eqz p0, :cond_0

    goto :goto_0

    .line 19
    :cond_0
    new-instance p0, Ljava/io/IOException;

    invoke-direct {p0}, Ljava/io/IOException;-><init>()V

    throw p0

    :cond_1
    :goto_0
    return-void
.end method

.method private static a(Ljava/io/File;Ljava/io/File;Z)V
    .locals 0

    if-eqz p2, :cond_0

    .line 20
    invoke-static {p1}, Lcom/salesforce/marketingcloud/util/d;->a(Ljava/io/File;)V

    .line 21
    :cond_0
    invoke-virtual {p0, p1}, Ljava/io/File;->renameTo(Ljava/io/File;)Z

    move-result p0

    if-eqz p0, :cond_1

    return-void

    .line 22
    :cond_1
    new-instance p0, Ljava/io/IOException;

    invoke-direct {p0}, Ljava/io/IOException;-><init>()V

    throw p0
.end method

.method private c(Ljava/lang/String;)V
    .locals 7

    const/16 v0, 0x20

    .line 1
    invoke-virtual {p1, v0}, Ljava/lang/String;->indexOf(I)I

    move-result v1

    const-string v2, "unexpected journal line: "

    const/4 v3, -0x1

    if-eq v1, v3, :cond_6

    add-int/lit8 v4, v1, 0x1

    .line 2
    invoke-virtual {p1, v0, v4}, Ljava/lang/String;->indexOf(II)I

    move-result v0

    if-ne v0, v3, :cond_0

    .line 3
    invoke-virtual {p1, v4}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v4

    const/4 v5, 0x6

    if-ne v1, v5, :cond_1

    .line 4
    const-string v5, "REMOVE"

    invoke-virtual {p1, v5}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v5

    if-eqz v5, :cond_1

    .line 5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/d;->h:Ljava/util/LinkedHashMap;

    invoke-virtual {p0, v4}, Ljava/util/AbstractMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    .line 6
    :cond_0
    invoke-virtual {p1, v4, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v4

    .line 7
    :cond_1
    iget-object v5, p0, Lcom/salesforce/marketingcloud/util/d;->h:Ljava/util/LinkedHashMap;

    invoke-virtual {v5, v4}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Lcom/salesforce/marketingcloud/util/d$d;

    if-nez v5, :cond_2

    .line 8
    new-instance v5, Lcom/salesforce/marketingcloud/util/d$d;

    invoke-direct {v5, p0, v4}, Lcom/salesforce/marketingcloud/util/d$d;-><init>(Lcom/salesforce/marketingcloud/util/d;Ljava/lang/String;)V

    .line 9
    iget-object v6, p0, Lcom/salesforce/marketingcloud/util/d;->h:Ljava/util/LinkedHashMap;

    invoke-virtual {v6, v4, v5}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_2
    const/4 v4, 0x5

    if-eq v0, v3, :cond_3

    if-ne v1, v4, :cond_3

    .line 10
    const-string v6, "CLEAN"

    invoke-virtual {p1, v6}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v6

    if-eqz v6, :cond_3

    const/4 p0, 0x1

    add-int/2addr v0, p0

    .line 11
    invoke-virtual {p1, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p1

    const-string v0, " "

    invoke-virtual {p1, v0}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object p1

    .line 12
    iput-boolean p0, v5, Lcom/salesforce/marketingcloud/util/d$d;->c:Z

    const/4 p0, 0x0

    .line 13
    iput-object p0, v5, Lcom/salesforce/marketingcloud/util/d$d;->d:Lcom/salesforce/marketingcloud/util/d$c;

    .line 14
    invoke-virtual {v5, p1}, Lcom/salesforce/marketingcloud/util/d$d;->b([Ljava/lang/String;)V

    return-void

    :cond_3
    if-ne v0, v3, :cond_4

    if-ne v1, v4, :cond_4

    .line 15
    const-string v4, "DIRTY"

    invoke-virtual {p1, v4}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v4

    if-eqz v4, :cond_4

    .line 16
    new-instance p1, Lcom/salesforce/marketingcloud/util/d$c;

    invoke-direct {p1, p0, v5}, Lcom/salesforce/marketingcloud/util/d$c;-><init>(Lcom/salesforce/marketingcloud/util/d;Lcom/salesforce/marketingcloud/util/d$d;)V

    iput-object p1, v5, Lcom/salesforce/marketingcloud/util/d$d;->d:Lcom/salesforce/marketingcloud/util/d$c;

    return-void

    :cond_4
    if-ne v0, v3, :cond_5

    const/4 p0, 0x4

    if-ne v1, p0, :cond_5

    .line 17
    const-string p0, "READ"

    invoke-virtual {p1, p0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result p0

    if-eqz p0, :cond_5

    return-void

    .line 18
    :cond_5
    new-instance p0, Ljava/io/IOException;

    invoke-virtual {v2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 19
    :cond_6
    new-instance p0, Ljava/io/IOException;

    invoke-virtual {v2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method private e(Ljava/lang/String;)V
    .locals 2

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/util/d;->v:Ljava/util/regex/Pattern;

    invoke-virtual {p0, p1}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    move-result-object p0

    .line 3
    invoke-virtual {p0}, Ljava/util/regex/Matcher;->matches()Z

    move-result p0

    if-eqz p0, :cond_0

    return-void

    .line 4
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string v0, "keys must match regex [a-z0-9_-]{1,120}: \""

    const-string v1, "\""

    .line 5
    invoke-static {v0, p1, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 6
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method private h()V
    .locals 8

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->e:Ljava/io/File;

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/util/d;->a(Ljava/io/File;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->h:Ljava/util/LinkedHashMap;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_3

    .line 21
    .line 22
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    check-cast v1, Lcom/salesforce/marketingcloud/util/d$d;

    .line 27
    .line 28
    iget-object v2, v1, Lcom/salesforce/marketingcloud/util/d$d;->d:Lcom/salesforce/marketingcloud/util/d$c;

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    if-nez v2, :cond_1

    .line 32
    .line 33
    :goto_1
    iget v2, p0, Lcom/salesforce/marketingcloud/util/d;->c:I

    .line 34
    .line 35
    if-ge v3, v2, :cond_0

    .line 36
    .line 37
    iget-wide v4, p0, Lcom/salesforce/marketingcloud/util/d;->l:J

    .line 38
    .line 39
    iget-object v2, v1, Lcom/salesforce/marketingcloud/util/d$d;->b:[J

    .line 40
    .line 41
    aget-wide v6, v2, v3

    .line 42
    .line 43
    add-long/2addr v4, v6

    .line 44
    iput-wide v4, p0, Lcom/salesforce/marketingcloud/util/d;->l:J

    .line 45
    .line 46
    add-int/lit8 v3, v3, 0x1

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    const/4 v2, 0x0

    .line 50
    iput-object v2, v1, Lcom/salesforce/marketingcloud/util/d$d;->d:Lcom/salesforce/marketingcloud/util/d$c;

    .line 51
    .line 52
    :goto_2
    iget v2, p0, Lcom/salesforce/marketingcloud/util/d;->c:I

    .line 53
    .line 54
    if-ge v3, v2, :cond_2

    .line 55
    .line 56
    invoke-virtual {v1, v3}, Lcom/salesforce/marketingcloud/util/d$d;->a(I)Ljava/io/File;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    invoke-static {v2}, Lcom/salesforce/marketingcloud/util/d;->a(Ljava/io/File;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v1, v3}, Lcom/salesforce/marketingcloud/util/d$d;->b(I)Ljava/io/File;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    invoke-static {v2}, Lcom/salesforce/marketingcloud/util/d;->a(Ljava/io/File;)V

    .line 68
    .line 69
    .line 70
    add-int/lit8 v3, v3, 0x1

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_2
    invoke-interface {v0}, Ljava/util/Iterator;->remove()V

    .line 74
    .line 75
    .line 76
    goto :goto_0

    .line 77
    :cond_3
    return-void
.end method

.method private i()V
    .locals 9

    .line 1
    const-string v0, ", "

    .line 2
    .line 3
    const-string v1, "unexpected journal header: ["

    .line 4
    .line 5
    new-instance v2, Lcom/salesforce/marketingcloud/util/i;

    .line 6
    .line 7
    new-instance v3, Ljava/io/FileInputStream;

    .line 8
    .line 9
    iget-object v4, p0, Lcom/salesforce/marketingcloud/util/d;->d:Ljava/io/File;

    .line 10
    .line 11
    invoke-direct {v3, v4}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V

    .line 12
    .line 13
    .line 14
    sget-object v4, Lcom/salesforce/marketingcloud/util/e;->a:Ljava/nio/charset/Charset;

    .line 15
    .line 16
    invoke-direct {v2, v3, v4}, Lcom/salesforce/marketingcloud/util/i;-><init>(Ljava/io/InputStream;Ljava/nio/charset/Charset;)V

    .line 17
    .line 18
    .line 19
    :try_start_0
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/util/i;->d()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/util/i;->d()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v4

    .line 27
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/util/i;->d()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/util/i;->d()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v6

    .line 35
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/util/i;->d()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v7

    .line 39
    const-string v8, "libcore.io.DiskLruCache"

    .line 40
    .line 41
    invoke-virtual {v8, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v8

    .line 45
    if-eqz v8, :cond_1

    .line 46
    .line 47
    const-string v8, "1"

    .line 48
    .line 49
    invoke-virtual {v8, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v8

    .line 53
    if-eqz v8, :cond_1

    .line 54
    .line 55
    iget v8, p0, Lcom/salesforce/marketingcloud/util/d;->g:I

    .line 56
    .line 57
    invoke-static {v8}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v8

    .line 61
    invoke-virtual {v8, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v5

    .line 65
    if-eqz v5, :cond_1

    .line 66
    .line 67
    iget v5, p0, Lcom/salesforce/marketingcloud/util/d;->c:I

    .line 68
    .line 69
    invoke-static {v5}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v5

    .line 73
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v5

    .line 77
    if-eqz v5, :cond_1

    .line 78
    .line 79
    const-string v5, ""

    .line 80
    .line 81
    invoke-virtual {v5, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v5
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 85
    if-eqz v5, :cond_1

    .line 86
    .line 87
    const/4 v0, 0x0

    .line 88
    :goto_0
    :try_start_1
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/util/i;->d()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    invoke-direct {p0, v1}, Lcom/salesforce/marketingcloud/util/d;->c(Ljava/lang/String;)V
    :try_end_1
    .catch Ljava/io/EOFException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 93
    .line 94
    .line 95
    add-int/lit8 v0, v0, 0x1

    .line 96
    .line 97
    goto :goto_0

    .line 98
    :catchall_0
    move-exception p0

    .line 99
    goto :goto_2

    .line 100
    :catch_0
    :try_start_2
    iget-object v1, p0, Lcom/salesforce/marketingcloud/util/d;->h:Ljava/util/LinkedHashMap;

    .line 101
    .line 102
    invoke-virtual {v1}, Ljava/util/AbstractMap;->size()I

    .line 103
    .line 104
    .line 105
    move-result v1

    .line 106
    sub-int/2addr v0, v1

    .line 107
    iput v0, p0, Lcom/salesforce/marketingcloud/util/d;->j:I

    .line 108
    .line 109
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/util/i;->b()Z

    .line 110
    .line 111
    .line 112
    move-result v0

    .line 113
    if-eqz v0, :cond_0

    .line 114
    .line 115
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/util/d;->j()V

    .line 116
    .line 117
    .line 118
    goto :goto_1

    .line 119
    :cond_0
    new-instance v0, Ljava/io/BufferedWriter;

    .line 120
    .line 121
    new-instance v1, Ljava/io/OutputStreamWriter;

    .line 122
    .line 123
    new-instance v3, Ljava/io/FileOutputStream;

    .line 124
    .line 125
    iget-object v4, p0, Lcom/salesforce/marketingcloud/util/d;->d:Ljava/io/File;

    .line 126
    .line 127
    const/4 v5, 0x1

    .line 128
    invoke-direct {v3, v4, v5}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;Z)V

    .line 129
    .line 130
    .line 131
    sget-object v4, Lcom/salesforce/marketingcloud/util/e;->a:Ljava/nio/charset/Charset;

    .line 132
    .line 133
    invoke-direct {v1, v3, v4}, Ljava/io/OutputStreamWriter;-><init>(Ljava/io/OutputStream;Ljava/nio/charset/Charset;)V

    .line 134
    .line 135
    .line 136
    invoke-direct {v0, v1}, Ljava/io/BufferedWriter;-><init>(Ljava/io/Writer;)V

    .line 137
    .line 138
    .line 139
    iput-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->i:Ljava/io/Writer;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 140
    .line 141
    :goto_1
    invoke-static {v2}, Lcom/salesforce/marketingcloud/util/e;->a(Ljava/io/Closeable;)V

    .line 142
    .line 143
    .line 144
    return-void

    .line 145
    :cond_1
    :try_start_3
    new-instance p0, Ljava/io/IOException;

    .line 146
    .line 147
    new-instance v5, Ljava/lang/StringBuilder;

    .line 148
    .line 149
    invoke-direct {v5, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 153
    .line 154
    .line 155
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 159
    .line 160
    .line 161
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 162
    .line 163
    .line 164
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 165
    .line 166
    .line 167
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 168
    .line 169
    .line 170
    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 171
    .line 172
    .line 173
    const-string v0, "]"

    .line 174
    .line 175
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 176
    .line 177
    .line 178
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object v0

    .line 182
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 186
    :goto_2
    invoke-static {v2}, Lcom/salesforce/marketingcloud/util/e;->a(Ljava/io/Closeable;)V

    .line 187
    .line 188
    .line 189
    throw p0
.end method


# virtual methods
.method public a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/util/d$c;
    .locals 2

    const-wide/16 v0, -0x1

    .line 24
    invoke-virtual {p0, p1, v0, v1}, Lcom/salesforce/marketingcloud/util/d;->a(Ljava/lang/String;J)Lcom/salesforce/marketingcloud/util/d$c;

    move-result-object p0

    return-object p0
.end method

.method public declared-synchronized a(Ljava/lang/String;J)Lcom/salesforce/marketingcloud/util/d$c;
    .locals 6

    const-string v0, "DIRTY "

    monitor-enter p0

    .line 25
    :try_start_0
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/util/d;->a()V

    .line 26
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/util/d;->e(Ljava/lang/String;)V

    .line 27
    iget-object v1, p0, Lcom/salesforce/marketingcloud/util/d;->h:Ljava/util/LinkedHashMap;

    invoke-virtual {v1, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/util/d$d;

    const-wide/16 v2, -0x1

    cmp-long v2, p2, v2

    const/4 v3, 0x0

    if-eqz v2, :cond_1

    if-eqz v1, :cond_0

    .line 28
    iget-wide v4, v1, Lcom/salesforce/marketingcloud/util/d$d;->e:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    cmp-long p2, v4, p2

    if-eqz p2, :cond_1

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_0
    :goto_0
    monitor-exit p0

    return-object v3

    :cond_1
    if-nez v1, :cond_2

    .line 29
    :try_start_1
    new-instance v1, Lcom/salesforce/marketingcloud/util/d$d;

    invoke-direct {v1, p0, p1}, Lcom/salesforce/marketingcloud/util/d$d;-><init>(Lcom/salesforce/marketingcloud/util/d;Ljava/lang/String;)V

    .line 30
    iget-object p2, p0, Lcom/salesforce/marketingcloud/util/d;->h:Ljava/util/LinkedHashMap;

    invoke-virtual {p2, p1, v1}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_1

    .line 31
    :cond_2
    iget-object p2, v1, Lcom/salesforce/marketingcloud/util/d$d;->d:Lcom/salesforce/marketingcloud/util/d$c;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-eqz p2, :cond_3

    monitor-exit p0

    return-object v3

    .line 32
    :cond_3
    :goto_1
    :try_start_2
    new-instance p2, Lcom/salesforce/marketingcloud/util/d$c;

    invoke-direct {p2, p0, v1}, Lcom/salesforce/marketingcloud/util/d$c;-><init>(Lcom/salesforce/marketingcloud/util/d;Lcom/salesforce/marketingcloud/util/d$d;)V

    .line 33
    iput-object p2, v1, Lcom/salesforce/marketingcloud/util/d$d;->d:Lcom/salesforce/marketingcloud/util/d$c;

    .line 34
    iget-object p3, p0, Lcom/salesforce/marketingcloud/util/d;->i:Ljava/io/Writer;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 p1, 0xa

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p3, p1}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 35
    iget-object p1, p0, Lcom/salesforce/marketingcloud/util/d;->i:Ljava/io/Writer;

    invoke-virtual {p1}, Ljava/io/Writer;->flush()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    monitor-exit p0

    return-object p2

    :goto_2
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    throw p1
.end method

.method public declared-synchronized a(J)V
    .locals 0

    monitor-enter p0

    .line 36
    :try_start_0
    iput-wide p1, p0, Lcom/salesforce/marketingcloud/util/d;->k:J

    .line 37
    iget-object p1, p0, Lcom/salesforce/marketingcloud/util/d;->a:Ljava/util/concurrent/ThreadPoolExecutor;

    iget-object p2, p0, Lcom/salesforce/marketingcloud/util/d;->n:Ljava/util/concurrent/Callable;

    invoke-virtual {p1, p2}, Ljava/util/concurrent/AbstractExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p0

    return-void

    :catchall_0
    move-exception p1

    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1
.end method

.method public declared-synchronized a(Lcom/salesforce/marketingcloud/util/d$c;Z)V
    .locals 9

    monitor-enter p0

    .line 38
    :try_start_0
    iget-object v0, p1, Lcom/salesforce/marketingcloud/util/d$c;->a:Lcom/salesforce/marketingcloud/util/d$d;

    .line 39
    iget-object v1, v0, Lcom/salesforce/marketingcloud/util/d$d;->d:Lcom/salesforce/marketingcloud/util/d$c;

    if-ne v1, p1, :cond_a

    const/4 v1, 0x0

    if-eqz p2, :cond_2

    .line 40
    iget-boolean v2, v0, Lcom/salesforce/marketingcloud/util/d$d;->c:Z

    if-nez v2, :cond_2

    move v2, v1

    .line 41
    :goto_0
    iget v3, p0, Lcom/salesforce/marketingcloud/util/d;->c:I

    if-ge v2, v3, :cond_2

    .line 42
    iget-object v3, p1, Lcom/salesforce/marketingcloud/util/d$c;->b:[Z

    aget-boolean v3, v3, v2

    if-eqz v3, :cond_1

    .line 43
    invoke-virtual {v0, v2}, Lcom/salesforce/marketingcloud/util/d$d;->b(I)Ljava/io/File;

    move-result-object v3

    invoke-virtual {v3}, Ljava/io/File;->exists()Z

    move-result v3

    if-nez v3, :cond_0

    .line 44
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/util/d$c;->a()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p0

    return-void

    :catchall_0
    move-exception p1

    goto/16 :goto_4

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 45
    :cond_1
    :try_start_1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/util/d$c;->a()V

    .line 46
    new-instance p1, Ljava/lang/IllegalStateException;

    new-instance p2, Ljava/lang/StringBuilder;

    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v0, "Newly created entry didn\'t create value for index "

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    .line 47
    :cond_2
    :goto_1
    iget p1, p0, Lcom/salesforce/marketingcloud/util/d;->c:I

    if-ge v1, p1, :cond_5

    .line 48
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/util/d$d;->b(I)Ljava/io/File;

    move-result-object p1

    if-eqz p2, :cond_3

    .line 49
    invoke-virtual {p1}, Ljava/io/File;->exists()Z

    move-result v2

    if-eqz v2, :cond_4

    .line 50
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/util/d$d;->a(I)Ljava/io/File;

    move-result-object v2

    .line 51
    invoke-virtual {p1, v2}, Ljava/io/File;->renameTo(Ljava/io/File;)Z

    .line 52
    iget-object p1, v0, Lcom/salesforce/marketingcloud/util/d$d;->b:[J

    aget-wide v3, p1, v1

    .line 53
    invoke-virtual {v2}, Ljava/io/File;->length()J

    move-result-wide v5

    .line 54
    iget-object p1, v0, Lcom/salesforce/marketingcloud/util/d$d;->b:[J

    aput-wide v5, p1, v1

    .line 55
    iget-wide v7, p0, Lcom/salesforce/marketingcloud/util/d;->l:J

    sub-long/2addr v7, v3

    add-long/2addr v7, v5

    iput-wide v7, p0, Lcom/salesforce/marketingcloud/util/d;->l:J

    goto :goto_2

    .line 56
    :cond_3
    invoke-static {p1}, Lcom/salesforce/marketingcloud/util/d;->a(Ljava/io/File;)V

    :cond_4
    :goto_2
    add-int/lit8 v1, v1, 0x1

    goto :goto_1

    .line 57
    :cond_5
    iget p1, p0, Lcom/salesforce/marketingcloud/util/d;->j:I

    const/4 v1, 0x1

    add-int/2addr p1, v1

    iput p1, p0, Lcom/salesforce/marketingcloud/util/d;->j:I

    const/4 p1, 0x0

    .line 58
    iput-object p1, v0, Lcom/salesforce/marketingcloud/util/d$d;->d:Lcom/salesforce/marketingcloud/util/d$c;

    .line 59
    iget-boolean p1, v0, Lcom/salesforce/marketingcloud/util/d$d;->c:Z

    or-int/2addr p1, p2

    const/16 v2, 0xa

    if-eqz p1, :cond_6

    .line 60
    iput-boolean v1, v0, Lcom/salesforce/marketingcloud/util/d$d;->c:Z

    .line 61
    iget-object p1, p0, Lcom/salesforce/marketingcloud/util/d;->i:Ljava/io/Writer;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "CLEAN "

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v3, v0, Lcom/salesforce/marketingcloud/util/d$d;->a:Ljava/lang/String;

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/util/d$d;->a()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    if-eqz p2, :cond_7

    .line 62
    iget-wide p1, p0, Lcom/salesforce/marketingcloud/util/d;->m:J

    const-wide/16 v1, 0x1

    add-long/2addr v1, p1

    iput-wide v1, p0, Lcom/salesforce/marketingcloud/util/d;->m:J

    iput-wide p1, v0, Lcom/salesforce/marketingcloud/util/d$d;->e:J

    goto :goto_3

    .line 63
    :cond_6
    iget-object p1, p0, Lcom/salesforce/marketingcloud/util/d;->h:Ljava/util/LinkedHashMap;

    iget-object p2, v0, Lcom/salesforce/marketingcloud/util/d$d;->a:Ljava/lang/String;

    invoke-virtual {p1, p2}, Ljava/util/AbstractMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 64
    iget-object p1, p0, Lcom/salesforce/marketingcloud/util/d;->i:Ljava/io/Writer;

    new-instance p2, Ljava/lang/StringBuilder;

    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "REMOVE "

    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v0, v0, Lcom/salesforce/marketingcloud/util/d$d;->a:Ljava/lang/String;

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1, p2}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 65
    :cond_7
    :goto_3
    iget-object p1, p0, Lcom/salesforce/marketingcloud/util/d;->i:Ljava/io/Writer;

    invoke-virtual {p1}, Ljava/io/Writer;->flush()V

    .line 66
    iget-wide p1, p0, Lcom/salesforce/marketingcloud/util/d;->l:J

    iget-wide v0, p0, Lcom/salesforce/marketingcloud/util/d;->k:J

    cmp-long p1, p1, v0

    if-gtz p1, :cond_8

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/util/d;->g()Z

    move-result p1

    if-eqz p1, :cond_9

    .line 67
    :cond_8
    iget-object p1, p0, Lcom/salesforce/marketingcloud/util/d;->a:Ljava/util/concurrent/ThreadPoolExecutor;

    iget-object p2, p0, Lcom/salesforce/marketingcloud/util/d;->n:Ljava/util/concurrent/Callable;

    invoke-virtual {p1, p2}, Ljava/util/concurrent/AbstractExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :cond_9
    monitor-exit p0

    return-void

    .line 68
    :cond_a
    :try_start_2
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1}, Ljava/lang/IllegalStateException;-><init>()V

    throw p1

    :goto_4
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw p1
.end method

.method public declared-synchronized b(Ljava/lang/String;)Lcom/salesforce/marketingcloud/util/d$e;
    .locals 10

    monitor-enter p0

    .line 1
    :try_start_0
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/util/d;->a()V

    .line 2
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/util/d;->e(Ljava/lang/String;)V

    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->h:Ljava/util/LinkedHashMap;

    invoke-virtual {v0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lcom/salesforce/marketingcloud/util/d$d;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    const/4 v1, 0x0

    if-nez v0, :cond_0

    monitor-exit p0

    return-object v1

    .line 4
    :cond_0
    :try_start_1
    iget-boolean v2, v0, Lcom/salesforce/marketingcloud/util/d$d;->c:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    if-nez v2, :cond_1

    monitor-exit p0

    return-object v1

    .line 5
    :cond_1
    :try_start_2
    iget v2, p0, Lcom/salesforce/marketingcloud/util/d;->c:I

    new-array v8, v2, [Ljava/io/InputStream;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    const/4 v2, 0x0

    move v3, v2

    .line 6
    :goto_0
    :try_start_3
    iget v4, p0, Lcom/salesforce/marketingcloud/util/d;->c:I
    :try_end_3
    .catch Ljava/io/FileNotFoundException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    if-ge v3, v4, :cond_2

    .line 7
    :try_start_4
    new-instance v4, Ljava/io/FileInputStream;

    invoke-virtual {v0, v3}, Lcom/salesforce/marketingcloud/util/d$d;->a(I)Ljava/io/File;

    move-result-object v5

    invoke-direct {v4, v5}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V

    aput-object v4, v8, v3
    :try_end_4
    .catch Ljava/io/FileNotFoundException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :catchall_0
    move-exception v0

    move-object p1, v0

    move-object v4, p0

    goto :goto_3

    :catch_0
    move-object v4, p0

    goto :goto_2

    .line 8
    :cond_2
    :try_start_5
    iget v1, p0, Lcom/salesforce/marketingcloud/util/d;->j:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, Lcom/salesforce/marketingcloud/util/d;->j:I

    .line 9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/util/d;->i:Ljava/io/Writer;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "READ "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v3, 0xa

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/io/Writer;->append(Ljava/lang/CharSequence;)Ljava/io/Writer;

    .line 10
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/util/d;->g()Z

    move-result v1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    if-eqz v1, :cond_3

    .line 11
    :try_start_6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/util/d;->a:Ljava/util/concurrent/ThreadPoolExecutor;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/util/d;->n:Ljava/util/concurrent/Callable;

    invoke-virtual {v1, v2}, Ljava/util/concurrent/AbstractExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 12
    :cond_3
    :try_start_7
    new-instance v3, Lcom/salesforce/marketingcloud/util/d$e;

    iget-wide v6, v0, Lcom/salesforce/marketingcloud/util/d$d;->e:J

    iget-object v9, v0, Lcom/salesforce/marketingcloud/util/d$d;->b:[J
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    move-object v4, p0

    move-object v5, p1

    :try_start_8
    invoke-direct/range {v3 .. v9}, Lcom/salesforce/marketingcloud/util/d$e;-><init>(Lcom/salesforce/marketingcloud/util/d;Ljava/lang/String;J[Ljava/io/InputStream;[J)V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_1

    monitor-exit v4

    return-object v3

    :catchall_1
    move-exception v0

    :goto_1
    move-object p1, v0

    goto :goto_3

    :catchall_2
    move-exception v0

    move-object v4, p0

    goto :goto_1

    .line 13
    :goto_2
    :try_start_9
    iget p0, v4, Lcom/salesforce/marketingcloud/util/d;->c:I

    if-ge v2, p0, :cond_4

    .line 14
    aget-object p0, v8, v2

    if-eqz p0, :cond_4

    .line 15
    invoke-static {p0}, Lcom/salesforce/marketingcloud/util/e;->a(Ljava/io/Closeable;)V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_1

    add-int/lit8 v2, v2, 0x1

    goto :goto_2

    :cond_4
    monitor-exit v4

    return-object v1

    :goto_3
    :try_start_a
    monitor-exit v4
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_1

    throw p1
.end method

.method public b()V
    .locals 0

    .line 16
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/util/d;->close()V

    .line 17
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/d;->b:Ljava/io/File;

    invoke-static {p0}, Lcom/salesforce/marketingcloud/util/e;->a(Ljava/io/File;)V

    return-void
.end method

.method public declared-synchronized c()V
    .locals 1

    monitor-enter p0

    .line 20
    :try_start_0
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/util/d;->a()V

    .line 21
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/util/d;->l()V

    .line 22
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->i:Ljava/io/Writer;

    invoke-virtual {v0}, Ljava/io/Writer;->flush()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p0

    return-void

    :catchall_0
    move-exception v0

    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v0
.end method

.method public declared-synchronized close()V
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->i:Ljava/io/Writer;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    monitor-exit p0

    .line 7
    return-void

    .line 8
    :cond_0
    :try_start_1
    new-instance v0, Ljava/util/ArrayList;

    .line 9
    .line 10
    iget-object v1, p0, Lcom/salesforce/marketingcloud/util/d;->h:Ljava/util/LinkedHashMap;

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    :cond_1
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-eqz v1, :cond_2

    .line 28
    .line 29
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    check-cast v1, Lcom/salesforce/marketingcloud/util/d$d;

    .line 34
    .line 35
    iget-object v1, v1, Lcom/salesforce/marketingcloud/util/d$d;->d:Lcom/salesforce/marketingcloud/util/d$c;

    .line 36
    .line 37
    if-eqz v1, :cond_1

    .line 38
    .line 39
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/util/d$c;->a()V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :catchall_0
    move-exception v0

    .line 44
    goto :goto_1

    .line 45
    :cond_2
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/util/d;->l()V

    .line 46
    .line 47
    .line 48
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->i:Ljava/io/Writer;

    .line 49
    .line 50
    invoke-virtual {v0}, Ljava/io/Writer;->close()V

    .line 51
    .line 52
    .line 53
    const/4 v0, 0x0

    .line 54
    iput-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->i:Ljava/io/Writer;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 55
    .line 56
    monitor-exit p0

    .line 57
    return-void

    .line 58
    :goto_1
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 59
    throw v0
.end method

.method public d()Ljava/io/File;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/d;->b:Ljava/io/File;

    return-object p0
.end method

.method public declared-synchronized d(Ljava/lang/String;)Z
    .locals 7

    monitor-enter p0

    .line 2
    :try_start_0
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/util/d;->a()V

    .line 3
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/util/d;->e(Ljava/lang/String;)V

    .line 4
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->h:Ljava/util/LinkedHashMap;

    invoke-virtual {v0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lcom/salesforce/marketingcloud/util/d$d;

    const/4 v1, 0x0

    if-eqz v0, :cond_5

    .line 5
    iget-object v2, v0, Lcom/salesforce/marketingcloud/util/d$d;->d:Lcom/salesforce/marketingcloud/util/d$c;

    if-eqz v2, :cond_0

    goto/16 :goto_2

    .line 6
    :cond_0
    :goto_0
    iget v2, p0, Lcom/salesforce/marketingcloud/util/d;->c:I

    if-ge v1, v2, :cond_3

    .line 7
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/util/d$d;->a(I)Ljava/io/File;

    move-result-object v2

    .line 8
    invoke-virtual {v2}, Ljava/io/File;->exists()Z

    move-result v3

    if-eqz v3, :cond_2

    invoke-virtual {v2}, Ljava/io/File;->delete()Z

    move-result v3

    if-eqz v3, :cond_1

    goto :goto_1

    .line 9
    :cond_1
    new-instance p1, Ljava/io/IOException;

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "failed to delete "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p1

    :catchall_0
    move-exception p1

    goto :goto_3

    .line 10
    :cond_2
    :goto_1
    iget-wide v2, p0, Lcom/salesforce/marketingcloud/util/d;->l:J

    iget-object v4, v0, Lcom/salesforce/marketingcloud/util/d$d;->b:[J

    aget-wide v5, v4, v1

    sub-long/2addr v2, v5

    iput-wide v2, p0, Lcom/salesforce/marketingcloud/util/d;->l:J

    const-wide/16 v2, 0x0

    .line 11
    aput-wide v2, v4, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    .line 12
    :cond_3
    iget v0, p0, Lcom/salesforce/marketingcloud/util/d;->j:I

    const/4 v1, 0x1

    add-int/2addr v0, v1

    iput v0, p0, Lcom/salesforce/marketingcloud/util/d;->j:I

    .line 13
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->i:Ljava/io/Writer;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "REMOVE "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v3, 0xa

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/io/Writer;->append(Ljava/lang/CharSequence;)Ljava/io/Writer;

    .line 14
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->h:Ljava/util/LinkedHashMap;

    invoke-virtual {v0, p1}, Ljava/util/AbstractMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/util/d;->g()Z

    move-result p1

    if-eqz p1, :cond_4

    .line 16
    iget-object p1, p0, Lcom/salesforce/marketingcloud/util/d;->a:Ljava/util/concurrent/ThreadPoolExecutor;

    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->n:Ljava/util/concurrent/Callable;

    invoke-virtual {p1, v0}, Ljava/util/concurrent/AbstractExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_4
    monitor-exit p0

    return v1

    :cond_5
    :goto_2
    monitor-exit p0

    return v1

    :goto_3
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1
.end method

.method public declared-synchronized e()J
    .locals 2

    monitor-enter p0

    .line 1
    :try_start_0
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/util/d;->k:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p0

    return-wide v0

    :catchall_0
    move-exception v0

    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v0
.end method

.method public declared-synchronized f()Z
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->i:Ljava/io/Writer;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/4 v0, 0x0

    .line 9
    :goto_0
    monitor-exit p0

    .line 10
    return v0

    .line 11
    :catchall_0
    move-exception v0

    .line 12
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 13
    throw v0
.end method

.method public g()Z
    .locals 2

    .line 1
    iget v0, p0, Lcom/salesforce/marketingcloud/util/d;->j:I

    .line 2
    .line 3
    const/16 v1, 0x7d0

    .line 4
    .line 5
    if-lt v0, v1, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/d;->h:Ljava/util/LinkedHashMap;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/util/AbstractMap;->size()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-lt v0, p0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method public declared-synchronized j()V
    .locals 6

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->i:Ljava/io/Writer;

    .line 3
    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/io/Writer;->close()V

    .line 7
    .line 8
    .line 9
    goto :goto_0

    .line 10
    :catchall_0
    move-exception v0

    .line 11
    goto/16 :goto_3

    .line 12
    .line 13
    :cond_0
    :goto_0
    new-instance v0, Ljava/io/BufferedWriter;

    .line 14
    .line 15
    new-instance v1, Ljava/io/OutputStreamWriter;

    .line 16
    .line 17
    new-instance v2, Ljava/io/FileOutputStream;

    .line 18
    .line 19
    iget-object v3, p0, Lcom/salesforce/marketingcloud/util/d;->e:Ljava/io/File;

    .line 20
    .line 21
    invoke-direct {v2, v3}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    .line 22
    .line 23
    .line 24
    sget-object v3, Lcom/salesforce/marketingcloud/util/e;->a:Ljava/nio/charset/Charset;

    .line 25
    .line 26
    invoke-direct {v1, v2, v3}, Ljava/io/OutputStreamWriter;-><init>(Ljava/io/OutputStream;Ljava/nio/charset/Charset;)V

    .line 27
    .line 28
    .line 29
    invoke-direct {v0, v1}, Ljava/io/BufferedWriter;-><init>(Ljava/io/Writer;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 30
    .line 31
    .line 32
    :try_start_1
    const-string v1, "libcore.io.DiskLruCache"

    .line 33
    .line 34
    invoke-virtual {v0, v1}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string v1, "\n"

    .line 38
    .line 39
    invoke-virtual {v0, v1}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    const-string v1, "1"

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    const-string v1, "\n"

    .line 48
    .line 49
    invoke-virtual {v0, v1}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    iget v1, p0, Lcom/salesforce/marketingcloud/util/d;->g:I

    .line 53
    .line 54
    invoke-static {v1}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    invoke-virtual {v0, v1}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    const-string v1, "\n"

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    iget v1, p0, Lcom/salesforce/marketingcloud/util/d;->c:I

    .line 67
    .line 68
    invoke-static {v1}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    invoke-virtual {v0, v1}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    const-string v1, "\n"

    .line 76
    .line 77
    invoke-virtual {v0, v1}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    const-string v1, "\n"

    .line 81
    .line 82
    invoke-virtual {v0, v1}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    iget-object v1, p0, Lcom/salesforce/marketingcloud/util/d;->h:Ljava/util/LinkedHashMap;

    .line 86
    .line 87
    invoke-virtual {v1}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    if-eqz v2, :cond_2

    .line 100
    .line 101
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v2

    .line 105
    check-cast v2, Lcom/salesforce/marketingcloud/util/d$d;

    .line 106
    .line 107
    iget-object v3, v2, Lcom/salesforce/marketingcloud/util/d$d;->d:Lcom/salesforce/marketingcloud/util/d$c;

    .line 108
    .line 109
    const/16 v4, 0xa

    .line 110
    .line 111
    if-eqz v3, :cond_1

    .line 112
    .line 113
    new-instance v3, Ljava/lang/StringBuilder;

    .line 114
    .line 115
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 116
    .line 117
    .line 118
    const-string v5, "DIRTY "

    .line 119
    .line 120
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    iget-object v2, v2, Lcom/salesforce/marketingcloud/util/d$d;->a:Ljava/lang/String;

    .line 124
    .line 125
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 129
    .line 130
    .line 131
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object v2

    .line 135
    invoke-virtual {v0, v2}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    goto :goto_1

    .line 139
    :catchall_1
    move-exception v1

    .line 140
    goto :goto_2

    .line 141
    :cond_1
    new-instance v3, Ljava/lang/StringBuilder;

    .line 142
    .line 143
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 144
    .line 145
    .line 146
    const-string v5, "CLEAN "

    .line 147
    .line 148
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    iget-object v5, v2, Lcom/salesforce/marketingcloud/util/d$d;->a:Ljava/lang/String;

    .line 152
    .line 153
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 154
    .line 155
    .line 156
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/util/d$d;->a()Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object v2

    .line 160
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 164
    .line 165
    .line 166
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v2

    .line 170
    invoke-virtual {v0, v2}, Ljava/io/Writer;->write(Ljava/lang/String;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 171
    .line 172
    .line 173
    goto :goto_1

    .line 174
    :cond_2
    :try_start_2
    invoke-virtual {v0}, Ljava/io/Writer;->close()V

    .line 175
    .line 176
    .line 177
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->d:Ljava/io/File;

    .line 178
    .line 179
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    .line 180
    .line 181
    .line 182
    move-result v0

    .line 183
    const/4 v1, 0x1

    .line 184
    if-eqz v0, :cond_3

    .line 185
    .line 186
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->d:Ljava/io/File;

    .line 187
    .line 188
    iget-object v2, p0, Lcom/salesforce/marketingcloud/util/d;->f:Ljava/io/File;

    .line 189
    .line 190
    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/util/d;->a(Ljava/io/File;Ljava/io/File;Z)V

    .line 191
    .line 192
    .line 193
    :cond_3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->e:Ljava/io/File;

    .line 194
    .line 195
    iget-object v2, p0, Lcom/salesforce/marketingcloud/util/d;->d:Ljava/io/File;

    .line 196
    .line 197
    const/4 v3, 0x0

    .line 198
    invoke-static {v0, v2, v3}, Lcom/salesforce/marketingcloud/util/d;->a(Ljava/io/File;Ljava/io/File;Z)V

    .line 199
    .line 200
    .line 201
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->f:Ljava/io/File;

    .line 202
    .line 203
    invoke-virtual {v0}, Ljava/io/File;->delete()Z

    .line 204
    .line 205
    .line 206
    new-instance v0, Ljava/io/BufferedWriter;

    .line 207
    .line 208
    new-instance v2, Ljava/io/OutputStreamWriter;

    .line 209
    .line 210
    new-instance v3, Ljava/io/FileOutputStream;

    .line 211
    .line 212
    iget-object v4, p0, Lcom/salesforce/marketingcloud/util/d;->d:Ljava/io/File;

    .line 213
    .line 214
    invoke-direct {v3, v4, v1}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;Z)V

    .line 215
    .line 216
    .line 217
    sget-object v1, Lcom/salesforce/marketingcloud/util/e;->a:Ljava/nio/charset/Charset;

    .line 218
    .line 219
    invoke-direct {v2, v3, v1}, Ljava/io/OutputStreamWriter;-><init>(Ljava/io/OutputStream;Ljava/nio/charset/Charset;)V

    .line 220
    .line 221
    .line 222
    invoke-direct {v0, v2}, Ljava/io/BufferedWriter;-><init>(Ljava/io/Writer;)V

    .line 223
    .line 224
    .line 225
    iput-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->i:Ljava/io/Writer;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 226
    .line 227
    monitor-exit p0

    .line 228
    return-void

    .line 229
    :goto_2
    :try_start_3
    invoke-virtual {v0}, Ljava/io/Writer;->close()V

    .line 230
    .line 231
    .line 232
    throw v1

    .line 233
    :goto_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 234
    throw v0
.end method

.method public declared-synchronized k()J
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/util/d;->l:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    monitor-exit p0

    .line 5
    return-wide v0

    .line 6
    :catchall_0
    move-exception v0

    .line 7
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 8
    throw v0
.end method

.method public l()V
    .locals 4

    .line 1
    :goto_0
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/util/d;->l:J

    .line 2
    .line 3
    iget-wide v2, p0, Lcom/salesforce/marketingcloud/util/d;->k:J

    .line 4
    .line 5
    cmp-long v0, v0, v2

    .line 6
    .line 7
    if-lez v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/d;->h:Ljava/util/LinkedHashMap;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    check-cast v0, Ljava/util/Map$Entry;

    .line 24
    .line 25
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    check-cast v0, Ljava/lang/String;

    .line 30
    .line 31
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/util/d;->d(Ljava/lang/String;)Z

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    return-void
.end method
