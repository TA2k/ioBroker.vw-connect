.class public abstract Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000J\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0003\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0010 \n\u0002\u0008\u000c\n\u0002\u0018\u0002\n\u0002\u0008\u0008\u0008&\u0018\u0000 22\u00020\u0001:\u00012B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0017\u0010\u0006\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u0004H\u0002\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\u0017\u0010\t\u001a\u00020\u00042\u0006\u0010\u0008\u001a\u00020\u0004H\u0002\u00a2\u0006\u0004\u0008\t\u0010\u0007J\u0019\u0010\u000c\u001a\u00020\u00042\n\u0010\u000b\u001a\u0006\u0012\u0002\u0008\u00030\n\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u0015\u0010\u000c\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u0004\u00a2\u0006\u0004\u0008\u000c\u0010\u0007J%\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u0005\u001a\u00020\u00042\u000c\u0010\u000f\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u000eH\u0016\u00a2\u0006\u0004\u0008\u0011\u0010\u0012J1\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u0005\u001a\u00020\u00042\n\u0008\u0002\u0010\u0014\u001a\u0004\u0018\u00010\u00132\u000c\u0010\u000f\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u000eH\u0016\u00a2\u0006\u0004\u0008\u0011\u0010\u0015J%\u0010\u0016\u001a\u00020\u00102\u0006\u0010\u0005\u001a\u00020\u00042\u000c\u0010\u000f\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u000eH\u0016\u00a2\u0006\u0004\u0008\u0016\u0010\u0012J1\u0010\u0016\u001a\u00020\u00102\u0006\u0010\u0005\u001a\u00020\u00042\n\u0008\u0002\u0010\u0014\u001a\u0004\u0018\u00010\u00132\u000c\u0010\u000f\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u000eH\u0016\u00a2\u0006\u0004\u0008\u0016\u0010\u0015J%\u0010\u0017\u001a\u00020\u00102\u0006\u0010\u0005\u001a\u00020\u00042\u000c\u0010\u000f\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u000eH\u0016\u00a2\u0006\u0004\u0008\u0017\u0010\u0012J1\u0010\u0017\u001a\u00020\u00102\u0006\u0010\u0005\u001a\u00020\u00042\n\u0008\u0002\u0010\u0014\u001a\u0004\u0018\u00010\u00132\u000c\u0010\u000f\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u000eH\u0016\u00a2\u0006\u0004\u0008\u0017\u0010\u0015J9\u0010\u001d\u001a\u00020\u00102\u0006\u0010\u0019\u001a\u00020\u00182\u0006\u0010\u0005\u001a\u00020\u00042\n\u0008\u0002\u0010\u001a\u001a\u0004\u0018\u00010\u00132\u000c\u0010\u000f\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u000eH\u0000\u00a2\u0006\u0004\u0008\u001b\u0010\u001cR(\u0010\u001f\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u001e8\u0016@\u0016X\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008\u001f\u0010 \u001a\u0004\u0008!\u0010\"\"\u0004\u0008#\u0010$R\"\u0010%\u001a\u00020\u00188\u0016@\u0016X\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008%\u0010&\u001a\u0004\u0008\'\u0010(\"\u0004\u0008)\u0010*R$\u0010,\u001a\u0004\u0018\u00010+8\u0016@\u0016X\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008,\u0010-\u001a\u0004\u0008.\u0010/\"\u0004\u00080\u00101\u00a8\u00063"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;",
        "",
        "<init>",
        "()V",
        "",
        "tag",
        "formatTag",
        "(Ljava/lang/String;)Ljava/lang/String;",
        "msg",
        "formatMsg",
        "Lhy0/d;",
        "clazz",
        "createTag",
        "(Lhy0/d;)Ljava/lang/String;",
        "Lkotlin/Function0;",
        "lazyMsg",
        "Llx0/b0;",
        "d",
        "(Ljava/lang/String;Lay0/a;)V",
        "",
        "throwable",
        "(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V",
        "w",
        "e",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;",
        "lvl",
        "t",
        "log$sfmcsdk_release",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V",
        "log",
        "",
        "redactedValues",
        "Ljava/util/List;",
        "getRedactedValues",
        "()Ljava/util/List;",
        "setRedactedValues",
        "(Ljava/util/List;)V",
        "logLevel",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;",
        "getLogLevel",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;",
        "setLogLevel",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;)V",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogListener;",
        "listener",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogListener;",
        "getListener",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogListener;",
        "setListener",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogListener;)V",
        "Companion",
        "sfmcsdk_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger$Companion;

.field private static final MAX_TAG_LENGTH:I = 0x17

.field private static final REDACTED_VALUE_REPLACEMENT_TEXT:Ljava/lang/String; = "[REDACTED]"


# instance fields
.field private listener:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogListener;

.field private logLevel:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;

.field private redactedValues:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger$Companion;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 5
    .line 6
    iput-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->redactedValues:Ljava/util/List;

    .line 7
    .line 8
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;->ERROR:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;

    .line 9
    .line 10
    iput-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->logLevel:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;

    .line 11
    .line 12
    return-void
.end method

.method public static synthetic d$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V
    .locals 0

    .line 1
    if-nez p5, :cond_1

    .line 2
    .line 3
    and-int/lit8 p4, p4, 0x2

    .line 4
    .line 5
    if-eqz p4, :cond_0

    .line 6
    .line 7
    const/4 p2, 0x0

    .line 8
    :cond_0
    invoke-virtual {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->d(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 13
    .line 14
    const-string p1, "Super calls with default arguments not supported in this target, function: d"

    .line 15
    .line 16
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method

.method public static synthetic e$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V
    .locals 0

    .line 1
    if-nez p5, :cond_1

    .line 2
    .line 3
    and-int/lit8 p4, p4, 0x2

    .line 4
    .line 5
    if-eqz p4, :cond_0

    .line 6
    .line 7
    const/4 p2, 0x0

    .line 8
    :cond_0
    invoke-virtual {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->e(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 13
    .line 14
    const-string p1, "Super calls with default arguments not supported in this target, function: e"

    .line 15
    .line 16
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method

.method private final formatMsg(Ljava/lang/String;)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-static {p1}, Landroid/text/TextUtils;->getTrimmedLength(Ljava/lang/CharSequence;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const-string p0, "FORMATTED LOG MESSAGE WAS EMPTY"

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->getRedactedValues()Ljava/util/List;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ljava/lang/Iterable;

    .line 15
    .line 16
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_2

    .line 25
    .line 26
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    check-cast v0, Ljava/lang/String;

    .line 31
    .line 32
    const-string v1, "[REDACTED]"

    .line 33
    .line 34
    invoke-virtual {v1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    if-nez v2, :cond_1

    .line 39
    .line 40
    const/4 v2, 0x1

    .line 41
    invoke-static {v2, p1, v0, v1}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    goto :goto_0

    .line 46
    :cond_2
    return-object p1
.end method

.method private final formatTag(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/16 v0, 0x17

    .line 6
    .line 7
    if-gt p0, v0, :cond_0

    .line 8
    .line 9
    return-object p1

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    invoke-virtual {p1, p0, v0}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public static synthetic log$sfmcsdk_release$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V
    .locals 0

    .line 1
    if-nez p6, :cond_1

    .line 2
    .line 3
    and-int/lit8 p5, p5, 0x4

    .line 4
    .line 5
    if-eqz p5, :cond_0

    .line 6
    .line 7
    const/4 p3, 0x0

    .line 8
    :cond_0
    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->log$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 13
    .line 14
    const-string p1, "Super calls with default arguments not supported in this target, function: log"

    .line 15
    .line 16
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method

.method public static synthetic w$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V
    .locals 0

    .line 1
    if-nez p5, :cond_1

    .line 2
    .line 3
    and-int/lit8 p4, p4, 0x2

    .line 4
    .line 5
    if-eqz p4, :cond_0

    .line 6
    .line 7
    const/4 p2, 0x0

    .line 8
    :cond_0
    invoke-virtual {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->w(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 13
    .line 14
    const-string p1, "Super calls with default arguments not supported in this target, function: w"

    .line 15
    .line 16
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method


# virtual methods
.method public final createTag(Lhy0/d;)Ljava/lang/String;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lhy0/d;",
            ")",
            "Ljava/lang/String;"
        }
    .end annotation

    const-string v0, "clazz"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-static {p1}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->createTag(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public final createTag(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    const-string v0, "tag"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->formatTag(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public d(Ljava/lang/String;Lay0/a;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    const-string v0, "tag"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "lazyMsg"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    .line 1
    invoke-virtual {p0, p1, v0, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->d(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    return-void
.end method

.method public d(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/Throwable;",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    const-string v0, "tag"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "lazyMsg"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;->DEBUG:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;

    invoke-virtual {p0, v0, p1, p2, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->log$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    return-void
.end method

.method public e(Ljava/lang/String;Lay0/a;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    const-string v0, "tag"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "lazyMsg"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    .line 1
    invoke-virtual {p0, p1, v0, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->e(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    return-void
.end method

.method public e(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/Throwable;",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    const-string v0, "tag"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "lazyMsg"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;->ERROR:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;

    invoke-virtual {p0, v0, p1, p2, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->log$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    return-void
.end method

.method public getListener()Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogListener;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->listener:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogListener;

    .line 2
    .line 3
    return-object p0
.end method

.method public getLogLevel()Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->logLevel:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRedactedValues()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->redactedValues:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final log$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;",
            "Ljava/lang/String;",
            "Ljava/lang/Throwable;",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "lvl"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "tag"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "lazyMsg"

    .line 12
    .line 13
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->getListener()Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogListener;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->getLogLevel()Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-virtual {p1, v1}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-ltz v1, :cond_0

    .line 31
    .line 32
    :try_start_0
    invoke-direct {p0, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->formatTag(Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p2

    .line 36
    invoke-interface {p4}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p4

    .line 40
    check-cast p4, Ljava/lang/String;

    .line 41
    .line 42
    invoke-direct {p0, p4}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->formatMsg(Ljava/lang/String;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-interface {v0, p1, p2, p0, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogListener;->out(Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :catch_0
    move-exception p0

    .line 51
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    const-string p2, "Exception was thrown by "

    .line 60
    .line 61
    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    const-string p2, "~$Logger"

    .line 66
    .line 67
    invoke-static {p2, p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 68
    .line 69
    .line 70
    :cond_0
    :goto_0
    return-void
.end method

.method public setListener(Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogListener;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->listener:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogListener;

    .line 2
    .line 3
    return-void
.end method

.method public setLogLevel(Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->logLevel:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;

    .line 7
    .line 8
    return-void
.end method

.method public setRedactedValues(Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->redactedValues:Ljava/util/List;

    .line 7
    .line 8
    return-void
.end method

.method public w(Ljava/lang/String;Lay0/a;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    const-string v0, "tag"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "lazyMsg"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    .line 1
    invoke-virtual {p0, p1, v0, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->w(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    return-void
.end method

.method public w(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/Throwable;",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    const-string v0, "tag"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "lazyMsg"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;->WARN:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;

    invoke-virtual {p0, v0, p1, p2, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/Logger;->log$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    return-void
.end method
