.class Lio/opentelemetry/sdk/internal/GlobUtil$GlobPatternPredicate;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Predicate;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/internal/GlobUtil;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "GlobPatternPredicate"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Ljava/util/function/Predicate<",
        "Ljava/lang/String;",
        ">;"
    }
.end annotation


# instance fields
.field private final globPattern:Ljava/lang/String;

.field private final pattern:Ljava/util/regex/Pattern;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method private constructor <init>(Ljava/lang/String;Ljava/util/regex/Pattern;)V
    .locals 0
    .param p2    # Ljava/util/regex/Pattern;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lio/opentelemetry/sdk/internal/GlobUtil$GlobPatternPredicate;->globPattern:Ljava/lang/String;

    .line 4
    iput-object p2, p0, Lio/opentelemetry/sdk/internal/GlobUtil$GlobPatternPredicate;->pattern:Ljava/util/regex/Pattern;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/util/regex/Pattern;Lio/opentelemetry/sdk/internal/GlobUtil$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/sdk/internal/GlobUtil$GlobPatternPredicate;-><init>(Ljava/lang/String;Ljava/util/regex/Pattern;)V

    return-void
.end method


# virtual methods
.method public bridge synthetic test(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/String;

    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/internal/GlobUtil$GlobPatternPredicate;->test(Ljava/lang/String;)Z

    move-result p0

    return p0
.end method

.method public test(Ljava/lang/String;)Z
    .locals 2

    .line 2
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/GlobUtil$GlobPatternPredicate;->globPattern:Ljava/lang/String;

    const-string v1, "*"

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 p0, 0x1

    return p0

    .line 3
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/GlobUtil$GlobPatternPredicate;->pattern:Ljava/util/regex/Pattern;

    if-eqz v0, :cond_1

    .line 4
    invoke-virtual {v0, p1}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    move-result-object p0

    invoke-virtual {p0}, Ljava/util/regex/Matcher;->matches()Z

    move-result p0

    return p0

    .line 5
    :cond_1
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/GlobUtil$GlobPatternPredicate;->globPattern:Ljava/lang/String;

    invoke-virtual {p0, p1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result p0

    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "GlobPatternPredicate{globPattern="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/GlobUtil$GlobPatternPredicate;->globPattern:Ljava/lang/String;

    .line 9
    .line 10
    const-string v1, "}"

    .line 11
    .line 12
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method
