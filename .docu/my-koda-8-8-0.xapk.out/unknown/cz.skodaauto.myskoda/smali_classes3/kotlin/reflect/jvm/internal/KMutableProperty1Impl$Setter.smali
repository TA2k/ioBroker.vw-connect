.class public final Lkotlin/reflect/jvm/internal/KMutableProperty1Impl$Setter;
.super Lkotlin/reflect/jvm/internal/KPropertyImpl$Setter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhy0/k;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lkotlin/reflect/jvm/internal/KMutableProperty1Impl;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Setter"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        "V:",
        "Ljava/lang/Object;",
        ">",
        "Lkotlin/reflect/jvm/internal/KPropertyImpl$Setter<",
        "TV;>;",
        "Lhy0/k;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0006\u0018\u0000*\u0004\u0008\u0002\u0010\u0001*\u0004\u0008\u0003\u0010\u00022\u0008\u0012\u0004\u0012\u00028\u00030\u00032\u000e\u0012\u0004\u0012\u00028\u0002\u0012\u0004\u0012\u00028\u00030\u0004B\u001b\u0012\u0012\u0010\u0006\u001a\u000e\u0012\u0004\u0012\u00028\u0002\u0012\u0004\u0012\u00028\u00030\u0005\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J \u0010\u000c\u001a\u00020\u000b2\u0006\u0010\t\u001a\u00028\u00022\u0006\u0010\n\u001a\u00028\u0003H\u0096\u0002\u00a2\u0006\u0004\u0008\u000c\u0010\rR&\u0010\u0006\u001a\u000e\u0012\u0004\u0012\u00028\u0002\u0012\u0004\u0012\u00028\u00030\u00058\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0006\u0010\u000e\u001a\u0004\u0008\u000f\u0010\u0010\u00a8\u0006\u0011"
    }
    d2 = {
        "Lkotlin/reflect/jvm/internal/KMutableProperty1Impl$Setter;",
        "T",
        "V",
        "Lkotlin/reflect/jvm/internal/KPropertyImpl$Setter;",
        "Lhy0/k;",
        "Lkotlin/reflect/jvm/internal/KMutableProperty1Impl;",
        "property",
        "<init>",
        "(Lkotlin/reflect/jvm/internal/KMutableProperty1Impl;)V",
        "receiver",
        "value",
        "Llx0/b0;",
        "invoke",
        "(Ljava/lang/Object;Ljava/lang/Object;)V",
        "Lkotlin/reflect/jvm/internal/KMutableProperty1Impl;",
        "getProperty",
        "()Lkotlin/reflect/jvm/internal/KMutableProperty1Impl;",
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


# instance fields
.field private final property:Lkotlin/reflect/jvm/internal/KMutableProperty1Impl;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lkotlin/reflect/jvm/internal/KMutableProperty1Impl<",
            "TT;TV;>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lkotlin/reflect/jvm/internal/KMutableProperty1Impl;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/reflect/jvm/internal/KMutableProperty1Impl<",
            "TT;TV;>;)V"
        }
    .end annotation

    .line 1
    const-string v0, "property"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Lkotlin/reflect/jvm/internal/KPropertyImpl$Setter;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/KMutableProperty1Impl$Setter;->property:Lkotlin/reflect/jvm/internal/KMutableProperty1Impl;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public bridge synthetic getProperty()Lhy0/z;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/KMutableProperty1Impl$Setter;->getProperty()Lkotlin/reflect/jvm/internal/KMutableProperty1Impl;

    move-result-object p0

    return-object p0
.end method

.method public getProperty()Lkotlin/reflect/jvm/internal/KMutableProperty1Impl;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lkotlin/reflect/jvm/internal/KMutableProperty1Impl<",
            "TT;TV;>;"
        }
    .end annotation

    .line 2
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/KMutableProperty1Impl$Setter;->property:Lkotlin/reflect/jvm/internal/KMutableProperty1Impl;

    return-object p0
.end method

.method public bridge synthetic getProperty()Lkotlin/reflect/jvm/internal/KPropertyImpl;
    .locals 0

    .line 3
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/KMutableProperty1Impl$Setter;->getProperty()Lkotlin/reflect/jvm/internal/KMutableProperty1Impl;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lkotlin/reflect/jvm/internal/KMutableProperty1Impl$Setter;->invoke(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object p0, Llx0/b0;->a:Llx0/b0;

    return-object p0
.end method

.method public invoke(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;TV;)V"
        }
    .end annotation

    .line 2
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/KMutableProperty1Impl$Setter;->getProperty()Lkotlin/reflect/jvm/internal/KMutableProperty1Impl;

    move-result-object p0

    invoke-virtual {p0, p1, p2}, Lkotlin/reflect/jvm/internal/KMutableProperty1Impl;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    return-void
.end method
