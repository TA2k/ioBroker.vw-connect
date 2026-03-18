.class public Lkotlin/reflect/jvm/internal/impl/renderer/KeywordStringsGenerated;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final KEYWORDS:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 29

    .line 1
    new-instance v0, Ljava/util/HashSet;

    .line 2
    .line 3
    const-string v27, "interface"

    .line 4
    .line 5
    const-string v28, "typeof"

    .line 6
    .line 7
    const-string v1, "package"

    .line 8
    .line 9
    const-string v2, "as"

    .line 10
    .line 11
    const-string v3, "typealias"

    .line 12
    .line 13
    const-string v4, "class"

    .line 14
    .line 15
    const-string v5, "this"

    .line 16
    .line 17
    const-string v6, "super"

    .line 18
    .line 19
    const-string v7, "val"

    .line 20
    .line 21
    const-string v8, "var"

    .line 22
    .line 23
    const-string v9, "fun"

    .line 24
    .line 25
    const-string v10, "for"

    .line 26
    .line 27
    const-string v11, "null"

    .line 28
    .line 29
    const-string v12, "true"

    .line 30
    .line 31
    const-string v13, "false"

    .line 32
    .line 33
    const-string v14, "is"

    .line 34
    .line 35
    const-string v15, "in"

    .line 36
    .line 37
    const-string v16, "throw"

    .line 38
    .line 39
    const-string v17, "return"

    .line 40
    .line 41
    const-string v18, "break"

    .line 42
    .line 43
    const-string v19, "continue"

    .line 44
    .line 45
    const-string v20, "object"

    .line 46
    .line 47
    const-string v21, "if"

    .line 48
    .line 49
    const-string v22, "try"

    .line 50
    .line 51
    const-string v23, "else"

    .line 52
    .line 53
    const-string v24, "while"

    .line 54
    .line 55
    const-string v25, "do"

    .line 56
    .line 57
    const-string v26, "when"

    .line 58
    .line 59
    filled-new-array/range {v1 .. v28}, [Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-direct {v0, v1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 68
    .line 69
    .line 70
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/renderer/KeywordStringsGenerated;->KEYWORDS:Ljava/util/Set;

    .line 71
    .line 72
    return-void
.end method
