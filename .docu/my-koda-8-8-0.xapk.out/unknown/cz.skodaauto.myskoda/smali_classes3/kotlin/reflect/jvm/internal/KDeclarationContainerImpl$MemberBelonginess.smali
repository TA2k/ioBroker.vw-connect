.class public final enum Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "MemberBelonginess"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0002\u0008\u0005\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\u0008\u0084\u0081\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00000\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u000e\u0010\u0006\u001a\u00020\u00072\u0006\u0010\u0008\u001a\u00020\tj\u0002\u0008\u0004j\u0002\u0008\u0005\u00a8\u0006\n"
    }
    d2 = {
        "Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;",
        "",
        "<init>",
        "(Ljava/lang/String;I)V",
        "DECLARED",
        "INHERITED",
        "accept",
        "",
        "member",
        "Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;",
        "kotlin-reflection"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;

.field public static final enum DECLARED:Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;

.field public static final enum INHERITED:Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;


# direct methods
.method private static final synthetic $values()[Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;
    .locals 2

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;->DECLARED:Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;->INHERITED:Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;

    .line 4
    .line 5
    filled-new-array {v0, v1}, [Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;

    .line 2
    .line 3
    const-string v1, "DECLARED"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;->DECLARED:Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;

    .line 10
    .line 11
    new-instance v0, Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;

    .line 12
    .line 13
    const-string v1, "INHERITED"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;->INHERITED:Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;

    .line 20
    .line 21
    invoke-static {}, Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;->$values()[Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;->$VALUES:[Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;

    .line 26
    .line 27
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;->$ENTRIES:Lsx0/a;

    .line 32
    .line 33
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;I)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;
    .locals 1

    .line 1
    const-class v0, Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;->$VALUES:[Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final accept(Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;)Z
    .locals 3

    .line 1
    const-string v0, "member"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1}, Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;->getKind()Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor$Kind;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor$Kind;->isReal()Z

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    sget-object v0, Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;->DECLARED:Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl$MemberBelonginess;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    const/4 v2, 0x1

    .line 18
    if-ne p0, v0, :cond_0

    .line 19
    .line 20
    move p0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move p0, v1

    .line 23
    :goto_0
    if-ne p1, p0, :cond_1

    .line 24
    .line 25
    return v2

    .line 26
    :cond_1
    return v1
.end method
