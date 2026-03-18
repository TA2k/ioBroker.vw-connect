.class public final Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;
.super Lkotlin/reflect/jvm/internal/KPropertyImpl$Getter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lkotlin/reflect/jvm/internal/KPropertyNImpl;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Getter"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<V:",
        "Ljava/lang/Object;",
        ">",
        "Lkotlin/reflect/jvm/internal/KPropertyImpl$Getter<",
        "TV;>;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0018\u0000*\u0006\u0008\u0001\u0010\u0001 \u00012\u0008\u0012\u0004\u0012\u0002H\u00010\u0002B\u0015\u0012\u000c\u0010\u0003\u001a\u0008\u0012\u0004\u0012\u00028\u00010\u0004\u00a2\u0006\u0004\u0008\u0005\u0010\u0006R\u001a\u0010\u0003\u001a\u0008\u0012\u0004\u0012\u00028\u00010\u0004X\u0096\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0007\u0010\u0008\u00a8\u0006\t"
    }
    d2 = {
        "Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;",
        "V",
        "Lkotlin/reflect/jvm/internal/KPropertyImpl$Getter;",
        "property",
        "Lkotlin/reflect/jvm/internal/KPropertyNImpl;",
        "<init>",
        "(Lkotlin/reflect/jvm/internal/KPropertyNImpl;)V",
        "getProperty",
        "()Lkotlin/reflect/jvm/internal/KPropertyNImpl;",
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
.field private final property:Lkotlin/reflect/jvm/internal/KPropertyNImpl;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lkotlin/reflect/jvm/internal/KPropertyNImpl<",
            "TV;>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lkotlin/reflect/jvm/internal/KPropertyNImpl;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/reflect/jvm/internal/KPropertyNImpl<",
            "+TV;>;)V"
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
    invoke-direct {p0}, Lkotlin/reflect/jvm/internal/KPropertyImpl$Getter;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;->property:Lkotlin/reflect/jvm/internal/KPropertyNImpl;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public bridge synthetic getProperty()Lhy0/z;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;->getProperty()Lkotlin/reflect/jvm/internal/KPropertyNImpl;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic getProperty()Lkotlin/reflect/jvm/internal/KPropertyImpl;
    .locals 0

    .line 2
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;->getProperty()Lkotlin/reflect/jvm/internal/KPropertyNImpl;

    move-result-object p0

    return-object p0
.end method

.method public getProperty()Lkotlin/reflect/jvm/internal/KPropertyNImpl;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lkotlin/reflect/jvm/internal/KPropertyNImpl<",
            "TV;>;"
        }
    .end annotation

    .line 3
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/KPropertyNImpl$Getter;->property:Lkotlin/reflect/jvm/internal/KPropertyNImpl;

    return-object p0
.end method
