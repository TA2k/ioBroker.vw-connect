.class public abstract Lkotlin/reflect/jvm/internal/impl/util/CheckResult;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/impl/util/CheckResult$IllegalFunctionName;,
        Lkotlin/reflect/jvm/internal/impl/util/CheckResult$IllegalSignature;,
        Lkotlin/reflect/jvm/internal/impl/util/CheckResult$SuccessCheck;
    }
.end annotation


# instance fields
.field private final isSuccess:Z


# direct methods
.method private constructor <init>(Z)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Lkotlin/reflect/jvm/internal/impl/util/CheckResult;->isSuccess:Z

    return-void
.end method

.method public synthetic constructor <init>(ZLkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/impl/util/CheckResult;-><init>(Z)V

    return-void
.end method


# virtual methods
.method public final isSuccess()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lkotlin/reflect/jvm/internal/impl/util/CheckResult;->isSuccess:Z

    .line 2
    .line 3
    return p0
.end method
