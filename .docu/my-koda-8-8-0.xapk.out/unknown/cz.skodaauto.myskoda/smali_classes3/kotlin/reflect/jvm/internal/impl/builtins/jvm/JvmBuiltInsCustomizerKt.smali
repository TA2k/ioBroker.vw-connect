.class public final Lkotlin/reflect/jvm/internal/impl/builtins/jvm/JvmBuiltInsCustomizerKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final GET_FIRST_LIST_NAME:Lkotlin/reflect/jvm/internal/impl/name/Name;

.field private static final GET_LAST_LIST_NAME:Lkotlin/reflect/jvm/internal/impl/name/Name;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-string v0, "getFirst"

    .line 2
    .line 3
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/name/Name;->identifier(Ljava/lang/String;)Lkotlin/reflect/jvm/internal/impl/name/Name;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "identifier(...)"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/builtins/jvm/JvmBuiltInsCustomizerKt;->GET_FIRST_LIST_NAME:Lkotlin/reflect/jvm/internal/impl/name/Name;

    .line 13
    .line 14
    const-string v0, "getLast"

    .line 15
    .line 16
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/name/Name;->identifier(Ljava/lang/String;)Lkotlin/reflect/jvm/internal/impl/name/Name;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/builtins/jvm/JvmBuiltInsCustomizerKt;->GET_LAST_LIST_NAME:Lkotlin/reflect/jvm/internal/impl/name/Name;

    .line 24
    .line 25
    return-void
.end method

.method public static final synthetic access$getGET_FIRST_LIST_NAME$p()Lkotlin/reflect/jvm/internal/impl/name/Name;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/builtins/jvm/JvmBuiltInsCustomizerKt;->GET_FIRST_LIST_NAME:Lkotlin/reflect/jvm/internal/impl/name/Name;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGET_LAST_LIST_NAME$p()Lkotlin/reflect/jvm/internal/impl/name/Name;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/builtins/jvm/JvmBuiltInsCustomizerKt;->GET_LAST_LIST_NAME:Lkotlin/reflect/jvm/internal/impl/name/Name;

    .line 2
    .line 3
    return-object v0
.end method
